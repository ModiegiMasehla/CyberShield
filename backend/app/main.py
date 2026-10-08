from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .database import Base, engine, SessionLocal
from .api import router
from .seed import seed

app=FastAPI(title="CyberShield API",version="1.0.0",description="Defensive cybersecurity learning and monitoring platform.")
origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()]
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_credentials=True,allow_methods=["GET","POST","PATCH"],allow_headers=["Authorization","Content-Type"])

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try: seed(db)
    finally: db.close()

app.include_router(router)

@app.get("/")
def root(): return {"name":"CyberShield","docs":"/docs","authorization_notice":"Only scan systems you own or have explicit permission to test."}
