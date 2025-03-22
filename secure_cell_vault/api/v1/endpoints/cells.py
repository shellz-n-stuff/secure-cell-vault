from fastapi import APIRouter, Depends, HTTPException, Security, status
from typing import List, Optional
from ....core.models import Cell, CellPermission, CellKey
from ....core.security import CellEncryption, KeyRotation
from ....schemas.cell import CellCreate, CellUpdate, CellInDB, CellWithPermissions
from ....core.deps import get_current_user, get_current_active_user, get_db
from sqlalchemy.orm import Session
from ....core.security import MasterKeyManager
from datetime import datetime, timedelta

router = APIRouter()

@router.post("/", response_model=CellInDB)
async def create_cell(
    *,
    db: Session = Depends(get_db),
    cell_in: CellCreate,
    current_user = Depends(get_current_active_user),
    key_manager: MasterKeyManager = Depends()
):
    """Create a new cell with initial key"""
    # Check if user has permission to create cells
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to create cells"
        )
    
    # Create the cell
    cell = Cell(**cell_in.dict(exclude_unset=True))
    db.add(cell)
    db.commit()
    db.refresh(cell)
    
    # Create initial cell key
    key_rotation = KeyRotation(cell.id)
    initial_key = key_rotation.rotate_key()
    
    # Encrypt the cell key with master key
    cell_encryption = CellEncryption(cell.id, key_manager.master_key)
    encrypted_key = cell_encryption.encrypt(initial_key.hex())
    
    # Store the encrypted key
    cell_key = CellKey(
        cell_id=cell.id,
        version=1,
        encrypted_key=encrypted_key,
        active=True
    )
    db.add(cell_key)
    
    # Grant admin permission to creator
    permission = CellPermission(
        cell_id=cell.id,
        user_id=current_user.id,
        permission="admin"
    )
    db.add(permission)
    
    db.commit()
    return cell

@router.get("/", response_model=List[CellInDB])
async def list_cells(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_active_user),
    skip: int = 0,
    limit: int = 100
):
    """List all cells the user has access to"""
    if current_user.is_superuser:
        cells = db.query(Cell).offset(skip).limit(limit).all()
    else:
        # Filter cells based on user permissions
        cells = (
            db.query(Cell)
            .join(CellPermission)
            .filter(CellPermission.user_id == current_user.id)
            .offset(skip)
            .limit(limit)
            .all()
        )
    return cells

@router.get("/{cell_id}", response_model=CellWithPermissions)
async def get_cell(
    *,
    db: Session = Depends(get_db),
    cell_id: str,
    current_user = Depends(get_current_active_user)
):
    """Get detailed information about a specific cell"""
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
                CellPermission.user_id == current_user.id
            )
            .first()
        )
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
    
    return cell

@router.put("/{cell_id}", response_model=CellInDB)
async def update_cell(
    *,
    db: Session = Depends(get_db),
    cell_id: str,
    cell_in: CellUpdate,
    current_user = Depends(get_current_active_user)
):
    """Update a cell's metadata"""
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
                CellPermission.permission == "admin"
            )
            .first()
        )
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
    
    # Update cell attributes
    for field, value in cell_in.dict(exclude_unset=True).items():
        setattr(cell, field, value)
    
    db.commit()
    db.refresh(cell)
    return cell

@router.post("/{cell_id}/rotate", response_model=CellInDB)
async def rotate_cell_key(
    *,
    db: Session = Depends(get_db),
    cell_id: str,
    current_user = Depends(get_current_active_user),
    key_manager: MasterKeyManager = Depends()
):
    """Rotate the encryption key for a cell"""
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
                CellPermission.permission == "admin"
            )
            .first()
        )
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
    
    # Get current key version
    current_key = (
        db.query(CellKey)
        .filter(CellKey.cell_id == cell_id, CellKey.active == True)
        .first()
    )
    
    # Create new key
    key_rotation = KeyRotation(cell.id)
    new_key = key_rotation.rotate_key()
    
    # Encrypt the new key with master key
    cell_encryption = CellEncryption(cell.id, key_manager.master_key)
    encrypted_key = cell_encryption.encrypt(new_key.hex())
    
    # Deactivate old key
    if current_key:
        current_key.active = False
    
    # Store new key
    cell_key = CellKey(
        cell_id=cell.id,
        version=current_key.version + 1 if current_key else 1,
        encrypted_key=encrypted_key,
        active=True
    )
    db.add(cell_key)
    
    # Update rotation schedule
    cell.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(cell)
    return cell

@router.delete("/{cell_id}")
async def delete_cell(
    *,
    db: Session = Depends(get_db),
    cell_id: str,
    current_user = Depends(get_current_active_user)
):
    """Delete a cell and all its secrets"""
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
                CellPermission.permission == "admin"
            )
            .first()
        )
        if not permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
    
    # Delete the cell (cascade will handle related records)
    db.delete(cell)
    db.commit()
    
    return {"status": "success"}