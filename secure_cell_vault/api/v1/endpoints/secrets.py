from fastapi import APIRouter, Depends, HTTPException, Security, status
from typing import List, Optional
from ....core.models import Secret, Cell, CellPermission, CellKey, SecretVersion
from ....core.security import CellEncryption
from ....schemas.secret import SecretCreate, SecretUpdate, SecretInDB, SecretWithHistory
from ....core.deps import get_current_user, get_current_active_user, get_db
from sqlalchemy.orm import Session
from ....core.security import MasterKeyManager
from datetime import datetime

router = APIRouter()

@router.post("/{cell_id}/secrets", response_model=SecretInDB)
async def create_secret(
    *,
    db: Session = Depends(get_db),
    cell_id: str,
    secret_in: SecretCreate,
    current_user = Depends(get_current_active_user),
    key_manager: MasterKeyManager = Depends()
):
    """Create a new secret in a cell"""
    # Check cell exists and user has write permission
    cell = db.query(Cell).filter(Cell.id == cell_id).first()
    if not cell:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cell not found"
        )
    
    # Check permissions
    if not current_user.is_superuser:
        permission = (
            db.query(CellPermission)
            .filter(
                CellPermission.cell_id == cell_id,
                CellPermission.user_id == current_user.id,
                CellPermission.permission.in_(["write", "admin"])
            )
            .first()
        )
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
    
    # Check if secret with same key exists
    existing_secret = (
        db.query(Secret)
        .filter(Secret.cell_id == cell_id, Secret.key == secret_in.key)
        .first()
    )
    if existing_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Secret with this key already exists in the cell"
        )
    
    # Get current cell key
    cell_key = (
        db.query(CellKey)
        .filter(CellKey.cell_id == cell_id, CellKey.active == True)
        .first()
    )
    if not cell_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No active encryption key found for cell"
        )
    
    # Decrypt the cell key
    cell_encryption = CellEncryption(cell_id, key_manager.master_key)
    key_bytes = bytes.fromhex(cell_encryption.decrypt(cell_key.encrypted_key))
    
    # Encrypt the secret value
    secret_encryption = CellEncryption(cell_id, key_bytes)
    encrypted_value = secret_encryption.encrypt(secret_in.value)
    
    # Create the secret
    secret = Secret(
        cell_id=cell_id,
        key=secret_in.key,
        value=encrypted_value,
        version=1,
        metadata=secret_in.metadata
    )
    db.add(secret)
    
    # Create initial version history
    version = SecretVersion(
        secret=secret,
        value=encrypted_value,
        version=1
    )
    db.add(version)
    
    db.commit()
    db.refresh(secret)
    
    # Return decrypted value
    secret.value = secret_in.value
    return secret

@router.get("/{cell_id}/secrets/{secret_key}", response_model=SecretWithHistory)
async def get_secret(
    *,
    db: Session = Depends(get_db),
    cell_id: str,
    secret_key: str,
    current_user = Depends(get_current_active_user),
    key_manager: MasterKeyManager = Depends(),
    version: Optional[int] = None
):
    """Get a specific secret from a cell"""
    # Check permissions
    if not current_user.is_superuser:
        permission = (
            db.query(CellPermission)
            .filter(
                CellPermission.cell_id == cell_id,
                CellPermission.user_id == current_user.id
            )
            .first()
        )
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
    
    # Get the secret
    secret = (
        db.query(Secret)
        .filter(Secret.cell_id == cell_id, Secret.key == secret_key)
        .first()
    )
    
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    # Get the appropriate version
    if version:
        secret_version = (
            db.query(SecretVersion)
            .filter(
                SecretVersion.secret_id == secret.id,
                SecretVersion.version == version
            )
            .first()
        )
        if not secret_version:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Secret version {version} not found"
            )
        encrypted_value = secret_version.value
    else:
        encrypted_value = secret.value
    
    # Get current cell key
    cell_key = (
        db.query(CellKey)
        .filter(CellKey.cell_id == cell_id, CellKey.active == True)
        .first()
    )
    
    # Decrypt the cell key
    cell_encryption = CellEncryption(cell_id, key_manager.master_key)
    key_bytes = bytes.fromhex(cell_encryption.decrypt(cell_key.encrypted_key))
    
    # Decrypt the secret value
    secret_encryption = CellEncryption(cell_id, key_bytes)
    secret.value = secret_encryption.decrypt(encrypted_value)
    
    return secret

@router.put("/{cell_id}/secrets/{secret_key}", response_model=SecretInDB)
async def update_secret(
    *,
    db: Session = Depends(get_db),
    cell_id: str,
    secret_key: str,
    secret_in: SecretUpdate,
    current_user = Depends(get_current_active_user),
    key_manager: MasterKeyManager = Depends()
):
    """Update a secret's value"""
    # Check permissions
    if not current_user.is_superuser:
        permission = (
            db.query(CellPermission)
            .filter(
                CellPermission.cell_id == cell_id,
                CellPermission.user_id == current_user.id,
                CellPermission.permission.in_(["write", "admin"])
            )
            .first()
        )
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
    
    # Get the secret
    secret = (
        db.query(Secret)
        .filter(Secret.cell_id == cell_id, Secret.key == secret_key)
        .first()
    )
    
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    # Get current cell key
    cell_key = (
        db.query(CellKey)
        .filter(CellKey.cell_id == cell_id, CellKey.active == True)
        .first()
    )
    
    # Decrypt the cell key
    cell_encryption = CellEncryption(cell_id, key_manager.master_key)
    key_bytes = bytes.fromhex(cell_encryption.decrypt(cell_key.encrypted_key))
    
    # Encrypt the new value
    secret_encryption = CellEncryption(cell_id, key_bytes)
    encrypted_value = secret_encryption.encrypt(secret_in.value)
    
    # Create new version
    version = SecretVersion(
        secret=secret,
        value=encrypted_value,
        version=secret.version + 1
    )
    db.add(version)
    
    # Update secret
    secret.value = encrypted_value
    secret.version += 1
    if secret_in.metadata:
        secret.metadata = secret_in.metadata
    
    db.commit()
    db.refresh(secret)
    
    # Return decrypted value
    secret.value = secret_in.value
    return secret

@router.delete("/{cell_id}/secrets/{secret_key}")
async def delete_secret(
    *,
    db: Session = Depends(get_db),
    cell_id: str,
    secret_key: str,
    current_user = Depends(get_current_active_user)
):
    """Delete a secret"""
    # Check permissions
    if not current_user.is_superuser:
        permission = (
            db.query(CellPermission)
            .filter(
                CellPermission.cell_id == cell_id,
                CellPermission.user_id == current_user.id,
                CellPermission.permission.in_(["write", "admin"])
            )
            .first()
        )
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
    
    # Get the secret
    secret = (
        db.query(Secret)
        .filter(Secret.cell_id == cell_id, Secret.key == secret_key)
        .first()
    )
    
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found"
        )
    
    # Delete the secret (cascade will handle versions)
    db.delete(secret)
    db.commit()
    
    return {"status": "success"}