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
    Admins can see all vulnerabilities. Users only see their program's vulnerabilities.
    """
    program_id = None
    if current_user.role != models.UserRole.admin:
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
    Admins can access any vulnerability. Users can only access their program's vulnerabilities.
    """
    # Fetch vulnerability with related program info for authorization
    vulnerability = await crud.vulnerability.get_with_program(db, id=id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Admins can access all vulnerabilities
    if current_user.role != models.UserRole.admin:
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
    Admins can update any vulnerability. Users can only update their program's vulnerabilities.
    """
    # Fetch vulnerability with related program info for authorization
    vulnerability = await crud.vulnerability.get_with_program(db, id=id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Admins can update all vulnerabilities
    if current_user.role != models.UserRole.admin:
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
    Export vulnerabilities to CSV using streaming response.
    Paginates the DB query to avoid loading all records into memory.
    """
    import csv
    import io
    from fastapi.responses import StreamingResponse

    # Determine program_id based on user role
    program_id = None
    if current_user.role != models.UserRole.admin:
        program_id = current_user.program_id

    PAGE_SIZE = 500

    async def csv_generator():
        """Yield CSV rows in chunks using paginated DB queries."""
        # Write CSV header
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Title', 'Severity', 'Status', 'Asset ID', 'Service ID', 'Created At'])
        yield output.getvalue()

        # Paginate through results
        offset = 0
        while True:
            batch = await crud.vulnerability.get_multi(
                db,
                skip=offset,
                limit=PAGE_SIZE,
                program_id=program_id
            )
            if not batch:
                break

            output = io.StringIO()
            writer = csv.writer(output)
            for vuln in batch:
                writer.writerow([
                    str(vuln.id),
                    vuln.title,
                    vuln.severity,
                    vuln.status,
                    str(vuln.asset_id),
                    str(vuln.service_id) if vuln.service_id else '',
                    vuln.created_at.isoformat() if vuln.created_at else ''
                ])
            yield output.getvalue()

            if len(batch) < PAGE_SIZE:
                break
            offset += PAGE_SIZE

    return StreamingResponse(
        csv_generator(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"}
    )
