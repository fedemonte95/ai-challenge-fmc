"""Scan CRUD and execution routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import schemas
from app.db import get_db
from app.scan_service import create_scan_with_analysis, get_scan_with_findings, list_scans_with_findings

router = APIRouter()


@router.post("", response_model=schemas.ScanOut)
def create_scan(payload: schemas.ScanCreate, db: Session = Depends(get_db)):
    try:
        return create_scan_with_analysis(db, payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("", response_model=list[schemas.ScanSummary])
def list_scans(db: Session = Depends(get_db), limit: int = 100):
    scans = list_scans_with_findings(db, limit=limit)
    out: list[schemas.ScanSummary] = []
    for s in scans:
        out.append(
            schemas.ScanSummary(
                id=s.id,
                source_name=s.source_name,
                source_kind=s.source_kind,
                risk_score=s.risk_score,
                created_at=s.created_at,
                finding_count=len(s.findings),
            )
        )
    return out


@router.get("/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan_with_findings(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
