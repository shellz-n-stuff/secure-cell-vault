from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, DateTime, JSON, Table
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from uuid import uuid4

Base = declarative_base()

class Cell(Base):
    """A cell is an isolated encryption context with its own keys and access controls"""
    __tablename__ = "cells"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    rotation_period = Column(Integer)  # in days
    metadata = Column(JSON)
    
    # Relationships
    secrets = relationship("Secret", back_populates="cell", cascade="all, delete-orphan")
    permissions = relationship("CellPermission", back_populates="cell", cascade="all, delete-orphan")
    key_versions = relationship("CellKey", back_populates="cell", cascade="all, delete-orphan")

class Secret(Base):
    """A secret stored within a cell"""
    __tablename__ = "secrets"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    cell_id = Column(String, ForeignKey("cells.id"))
    key = Column(String, index=True)
    value = Column(String)
    version = Column(Integer)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    metadata = Column(JSON)
    
    # Relationships
    cell = relationship("Cell", back_populates="secrets")
    history = relationship("SecretVersion", back_populates="secret", cascade="all, delete-orphan")

class SecretVersion(Base):
    """Historical versions of secrets"""
    __tablename__ = "secret_versions"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    secret_id = Column(String, ForeignKey("secrets.id"))
    value = Column(String)
    version = Column(Integer)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    secret = relationship("Secret", back_populates="history")

class User(Base):
    """System user"""
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)
    
    # Relationships
    permissions = relationship("CellPermission", back_populates="user", cascade="all, delete-orphan")
    access_tokens = relationship("AccessToken", back_populates="user", cascade="all, delete-orphan")

class CellPermission(Base):
    """Access control for cells"""
    __tablename__ = "cell_permissions"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    cell_id = Column(String, ForeignKey("cells.id"))
    user_id = Column(String, ForeignKey("users.id"))
    permission = Column(String)  # read, write, admin
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    cell = relationship("Cell", back_populates="permissions")
    user = relationship("User", back_populates="permissions")

class CellKey(Base):
    """Key versions for cells"""
    __tablename__ = "cell_keys"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    cell_id = Column(String, ForeignKey("cells.id"))
    version = Column(Integer)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    active = Column(Boolean, default=True)
    encrypted_key = Column(String)  # Encrypted with master key
    
    # Relationships
    cell = relationship("Cell", back_populates="key_versions")

class AccessToken(Base):
    """API access tokens"""
    __tablename__ = "access_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    token_hash = Column(String)
    description = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="access_tokens")

class AuditLog(Base):
    """Audit trail for all system actions"""
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(String, ForeignKey("users.id"))
    action = Column(String)
    resource_type = Column(String)
    resource_id = Column(String)
    cell_id = Column(String, ForeignKey("cells.id"), nullable=True)
    metadata = Column(JSON)
    ip_address = Column(String)
    user_agent = Column(String)

class RotationSchedule(Base):
    """Schedules for key rotation"""
    __tablename__ = "rotation_schedules"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    cell_id = Column(String, ForeignKey("cells.id"))
    interval_days = Column(Integer)
    last_rotation = Column(DateTime(timezone=True))
    next_rotation = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    
    # Relationships
    cell = relationship("Cell")

# Many-to-many relationship tables
user_groups = Table('user_groups', Base.metadata,
    Column('user_id', String, ForeignKey('users.id')),
    Column('group_id', String, ForeignKey('groups.id'))
)

class Group(Base):
    """User groups for role-based access control"""
    __tablename__ = "groups"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    name = Column(String, unique=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    users = relationship("User", secondary=user_groups, backref="groups")