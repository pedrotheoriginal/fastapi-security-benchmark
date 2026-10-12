"""
API BLINDADA: versão refatorada com boas práticas de AppSec (OWASP).

Controles aplicados:
  - Validação estrita de entrada (Pydantic: gt, le, allow_inf_nan=False, extra=forbid) -> CWE-20 / CWE-1287
  - Valor monetário com Decimal e armazenado em centavos (inteiro)                    -> CWE-681
  - Transação atômica com BEGIN IMMEDIATE (lock de escrita desde o início)           -> CWE-362 / CWE-367
  - Atualização condicional (WHERE saldo >= valor) validada via rowcount             -> defesa em profundidade
  - CHECK constraint no banco (saldo nunca negativo)                                 -> defesa em profundidade
  - Erros genéricos ao cliente; detalhes apenas no log, identificados por error_id   -> CWE-209
"""
import logging
import uuid
from contextlib import asynccontextmanager
from decimal import Decimal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import CheckConstraint, String, create_engine, event, func, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger("secure_api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

DATABASE_URL = "sqlite:///./secure.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def _disable_driver_transactions(dbapi_conn, _record):
    # Desliga o controle implícito do driver sqlite3; o controle passa a ser do SQLAlchemy.
    dbapi_conn.isolation_level = None


@event.listens_for(engine, "begin")
def _begin_immediate(conn):
    # Adquire o lock de escrita do SQLite no início da transação.
    # Impede que duas transferências leiam o mesmo saldo simultaneamente.
    conn.exec_driver_sql("BEGIN IMMEDIATE")


class Base(DeclarativeBase):
    pass


class Wallet(Base):
    __tablename__ = "wallets"
    __table_args__ = (
        CheckConstraint("balance_cents >= 0", name="ck_balance_non_negative"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    owner: Mapped[str] = mapped_column(String(100))
    balance_cents: Mapped[int] = mapped_column(nullable=False)


class TransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_id: int = Field(gt=0)
    to_id: int = Field(gt=0)
    amount: Decimal = Field(
        gt=0,
        le=Decimal("1000000.00"),
        max_digits=12,
        decimal_places=2,
        allow_inf_nan=False,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        if db.scalar(select(func.count(Wallet.id))) == 0:
            db.add_all([
                Wallet(id=1, owner="alice", balance_cents=10_000),  # 100.00
                Wallet(id=2, owner="bob", balance_cents=10_000),    # 100.00
            ])
            db.commit()
    yield


app = FastAPI(title="Secure Wallet API", lifespan=lifespan)


@app.exception_handler(Exception)
async def unhandled_exception(_request: Request, exc: Exception):
    error_id = uuid.uuid4().hex
    logger.exception("Erro interno [error_id=%s]: %r", error_id, exc)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "error_id": error_id},
    )


@app.get("/wallets/{wallet_id}")
def get_wallet(wallet_id: int):
    with Session(engine) as db:
        wallet = db.get(Wallet, wallet_id)
        if wallet is None:
            raise HTTPException(status_code=404, detail="Carteira não encontrada")
        return {
            "id": wallet.id,
            "owner": wallet.owner,
            "balance": f"{wallet.balance_cents / 100:.2f}",
        }


@app.post("/transfer")
def transfer(payload: TransferRequest):
    if payload.from_id == payload.to_id:
        raise HTTPException(status_code=422, detail="Origem e destino devem ser diferentes.")

    amount_cents = int(payload.amount * 100)  # Conversão exata, sem float

    with Session(engine) as db, db.begin():
        # Débito atômico e condicional: só executa se houver saldo suficiente.
        debit = db.execute(
            update(Wallet)
            .where(Wallet.id == payload.from_id, Wallet.balance_cents >= amount_cents)
            .values(balance_cents=Wallet.balance_cents - amount_cents)
        )
        if debit.rowcount != 1:
            # Mensagem genérica: não revela se a carteira existe ou se o saldo é insuficiente.
            raise HTTPException(status_code=409, detail="Transferência não pode ser concluída.")

        credit = db.execute(
            update(Wallet)
            .where(Wallet.id == payload.to_id)
            .values(balance_cents=Wallet.balance_cents + amount_cents)
        )
        if credit.rowcount != 1:
            # Exceção dentro de db.begin() dispara ROLLBACK automático do débito.
            raise HTTPException(status_code=409, detail="Transferência não pode ser concluída.")

    return {"status": "completed"}
