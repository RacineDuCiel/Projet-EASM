from typing import Any, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from src import crud, models, schemas
from src.api.v1.endpoints import auth
from src.db.session import get_db
from src.models.enums import Severity, VulnStatus

router = APIRouter()

@router.get("/", response_model=List[schemas.Vulnerability])
async def read_vulnerabilities(
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    severity: Optional[Severity] = None,
    status: Optional[VulnStatus] = None,
    asset_id: Optional[UUID] = None,
    search: Optional[str] = None,
    current_user: models.User = Depends(auth.get_current_user),
) -> Any:
    """
    Retrieve vulnerabilities.
    """
    program_id = None
    if current_user.role == models.UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins cannot access vulnerabilities. This is an operational task for users."
        )
    
    program_id = current_user.program_id
        
    vulnerabilities = await crud.vulnerability.get_multi(
        db,
        skip=skip,
        limit=limit,
        program_id=program_id,
        severity=severity,
        status=status,
        asset_id=asset_id,
        search=search
    )
    return vulnerabilities

@router.get("/{id}", response_model=schemas.Vulnerability)
async def read_vulnerability(
    id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> Any:
    """
    Get vulnerability by ID.
    """
    # Check permissions first
    if current_user.role == models.UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins cannot access vulnerabilities."
        )

    # Fetch vulnerability with related program info for authorization
    vulnerability = await crud.vulnerability.get_with_program(db, id=id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Verify vulnerability belongs to user's program
    if vulnerability.asset and vulnerability.asset.scope:
        if vulnerability.asset.scope.program_id != current_user.program_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this vulnerability"
            )
    else:
        # Orphaned vulnerability - deny access for safety
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this vulnerability"
        )

    return vulnerability

@router.patch("/{id}", response_model=schemas.Vulnerability)
async def update_vulnerability(
    id: UUID,
    vuln_in: schemas.VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
) -> Any:
    """
    Update vulnerability status.
    """
    # Check permissions first
    if current_user.role == models.UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins cannot update vulnerabilities."
        )

    # Fetch vulnerability with related program info for authorization
    vulnerability = await crud.vulnerability.get_with_program(db, id=id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Verify vulnerability belongs to user's program
    if vulnerability.asset and vulnerability.asset.scope:
        if vulnerability.asset.scope.program_id != current_user.program_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to update this vulnerability"
            )
    else:
        # Orphaned vulnerability - deny access for safety
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this vulnerability"
        )

    vulnerability = await crud.vulnerability.update(db, db_obj=vulnerability, obj_in=vuln_in)
    return vulnerability

@router.get("/export/csv")
async def export_vulnerabilities(
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    """
    Export vulnerabilities to CSV.
    """
    import csv
    import io
    from fastapi.responses import StreamingResponse

    # Reuse the logic to fetch vulnerabilities based on user role
    program_id = None
    if current_user.role != models.UserRole.admin:
        program_id = current_user.program_id

    # Fetch all vulnerabilities (no pagination for export)
    # We might need a new CRUD method or just use get_multi with large limit
    # For now, let's use a large limit
    vulnerabilities = await crud.vulnerability.get_multi(
        db,
        skip=0,
        limit=10000, # Reasonable limit for MVP
        program_id=program_id
    )

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['ID', 'Title', 'Severity', 'Status', 'Asset ID', 'Service ID', 'Created At'])
    
    # Data
    for vuln in vulnerabilities:
        writer.writerow([
            str(vuln.id),
            vuln.title,
            vuln.severity,
            vuln.status,
            str(vuln.asset_id),
            str(vuln.service_id) if vuln.service_id else '',
            vuln.created_at.isoformat() if vuln.created_at else ''
        ])
    
    output.seek(0)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"}
    )
