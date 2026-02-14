"""Pydantic schemas for authentication API."""

from datetime import datetime
from typing import Optional, List, Any, Dict

from pydantic import BaseModel, EmailStr, Field, field_validator


class UserRegisterRequest(BaseModel):
    """Request model for user registration."""

    username: str = Field(..., min_length=3, max_length=50, description="Username for the new account")
    email: EmailStr = Field(..., description="Email address for the new account")
    password: str = Field(..., min_length=8, description="Password (minimum 8 characters)")
    full_name: Optional[str] = Field(None, max_length=100, description="Full name of the user")
    is_superuser: bool = Field(False, description="Make user a superuser (admin only)")

    @field_validator('username')
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        """Validate username is alphanumeric with optional _ or -."""
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must be alphanumeric (with optional _ or - characters)')
        return v


class UserLoginRequest(BaseModel):
    """Request model for user login."""

    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class TokenResponse(BaseModel):
    """Response model for token issuance."""

    access_token: str = Field(..., description="JWT access token")
    refresh_token: Optional[str] = Field(None, description="JWT refresh token (optional)")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")
    expires_in: int = Field(..., description="Token expiration time in seconds")


class RefreshTokenRequest(BaseModel):
    """Request model for token refresh."""

    refresh_token: str = Field(..., description="Refresh token to exchange for new access token")


class LogoutRequest(BaseModel):
    """Request model for logout."""

    access_token: str = Field(..., description="Access token to blacklist")
    refresh_token: Optional[str] = Field(None, description="Refresh token to revoke (optional)")


class UserResponse(BaseModel):
    """Response model for user information."""

    id: int = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")
    full_name: Optional[str] = Field(None, description="Full name")
    is_active: bool = Field(..., description="Whether user account is active")
    is_superuser: bool = Field(..., description="Whether user has superuser privileges")
    created_at: datetime = Field(..., description="Account creation timestamp")
    last_login_at: Optional[datetime] = Field(None, description="Last login timestamp")


class ErrorResponse(BaseModel):
    """Response model for errors."""

    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Machine-readable error code")


class ClientRegistrationRequest(BaseModel):
    """OAuth Dynamic Client Registration request model (RFC 7591)."""

    redirect_uris: List[str] = Field(..., description="Registered redirect URIs")
    token_endpoint_auth_method: Optional[str] = Field(
        None,
        description="Client auth method at token endpoint (none, client_secret_basic, client_secret_post)"
    )
    grant_types: Optional[List[str]] = Field(None, description="OAuth2 grant types")
    response_types: Optional[List[str]] = Field(None, description="OAuth2 response types")
    client_name: Optional[str] = Field(None, description="Human-readable client name")
    client_uri: Optional[str] = Field(None, description="Client home page URI")
    logo_uri: Optional[str] = Field(None, description="Client logo URI")
    scope: Optional[str] = Field(None, description="Requested scope")
    contacts: Optional[List[str]] = Field(None, description="List of contact emails")
    tos_uri: Optional[str] = Field(None, description="Terms of service URI")
    policy_uri: Optional[str] = Field(None, description="Privacy policy URI")
    jwks_uri: Optional[str] = Field(None, description="JWKS URI")
    jwks: Optional[Dict[str, Any]] = Field(None, description="JWKS object")
    software_id: Optional[str] = Field(None, description="Software ID")
    software_version: Optional[str] = Field(None, description="Software version")


class ClientRegistrationResponse(BaseModel):
    """OAuth Dynamic Client Registration response model (RFC 7591/7592)."""

    client_id: str = Field(..., description="Client identifier")
    client_secret: Optional[str] = Field(None, description="Client secret (if applicable)")
    client_id_issued_at: Optional[int] = Field(None, description="Client ID issuance time (epoch seconds)")
    client_secret_expires_at: Optional[int] = Field(0, description="Client secret expiration time (epoch seconds)")
    registration_access_token: Optional[str] = Field(None, description="Token for client management")
    registration_client_uri: Optional[str] = Field(None, description="Client management URI")
    redirect_uris: List[str] = Field(..., description="Registered redirect URIs")
    token_endpoint_auth_method: Optional[str] = Field(None, description="Token endpoint auth method")
    grant_types: Optional[List[str]] = Field(None, description="OAuth2 grant types")
    response_types: Optional[List[str]] = Field(None, description="OAuth2 response types")
    client_name: Optional[str] = Field(None, description="Client name")
    client_uri: Optional[str] = Field(None, description="Client home page URI")
    logo_uri: Optional[str] = Field(None, description="Client logo URI")
    scope: Optional[str] = Field(None, description="Approved scope")
    contacts: Optional[List[str]] = Field(None, description="Contact emails")
    tos_uri: Optional[str] = Field(None, description="Terms of service URI")
    policy_uri: Optional[str] = Field(None, description="Privacy policy URI")
    jwks_uri: Optional[str] = Field(None, description="JWKS URI")
    jwks: Optional[Dict[str, Any]] = Field(None, description="JWKS object")
    software_id: Optional[str] = Field(None, description="Software ID")
    software_version: Optional[str] = Field(None, description="Software version")
