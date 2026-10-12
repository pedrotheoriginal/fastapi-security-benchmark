"""
API VULNERÁVEL: estudo de caso de AppSec.
NÃO USE EM PRODUÇÃO.

Falhas intencionais:
  1. Race Condition (Check-Then-Act) sem transação atômica  -> CWE-362 / CWE-367
  2. Validação ausente do valor monetário (negativo, inf, nan) -> CWE-20 / CWE-839
  3. Valor monetário em float (imprecisão binária)           -> CWE-681
  4. Vazamento de stack trace ao cliente                     -> CWE-209
"""
import time
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import Float, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = "sqlite:///./vulnerable.db"
SIMULATED_LATENCY_S = 0.2  # Amplia a janela entre o "check" e o "act"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)


class Base(DeclarativeBase):
    pass


class Wallet(Base):
    __tablename__ = "wallets"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner: Mapped[str] = mapped_column(String(100))
    balance: Mapped[float] = mapped_column(Float, nullable=False)


class TransferIn(BaseModel):
    from_id: int
    to_id: int
    amount: float  # ⚠️ Sem validação: aceita negativo, Infinity e NaN


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if db.scalar(select(func.count(Wallet.id))) == 0:
            db.add_all([
                Wallet(id=1, owner="alice", balance=100.0),
                Wallet(id=2, owner="bob", balance=100.0),
            ])
            db.commit()
    yield


app = FastAPI(title="Vulnerable Wallet API", lifespan=lifespan)


@app.get("/wallets/{wallet_id}")
def get_wallet(wallet_id: int):
    with SessionLocal() as db:
        wallet = db.get(Wallet, wallet_id)
        if wallet is None:
            raise HTTPException(status_code=404, detail="Carteira não encontrada")
        return {"id": wallet.id, "owner": wallet.owner, "balance": wallet.balance}


@app.post("/transfer")
def transfer(payload: TransferIn):
    db = SessionLocal()
    try:
        src = db.get(Wallet, payload.from_id)
        dst = db.get(Wallet, payload.to_id)
        if src is None or dst is None:
            raise HTTPException(status_code=404, detail="Carteira não encontrada")

        # 1) CHECK: lê o saldo atual
        if src.balance < payload.amount:
            raise HTTPException(status_code=400, detail="Saldo insuficiente")

        time.sleep(SIMULATED_LATENCY_S)  # Simula I/O / latência de rede

        # 2) ACT: grava com base no saldo lido ANTES do sleep (lost update)
        src.balance = src.balance - payload.amount
        dst.balance = dst.balance + payload.amount
        db.commit()
        return {"status": "ok"}

    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        # ⚠️ Vazamento de detalhes internos ao cliente
        return JSONResponse(
            status_code=500,
            content={"error": repr(exc), "traceback": traceback.format_exc()},
        )
    finally:
        db.close()
