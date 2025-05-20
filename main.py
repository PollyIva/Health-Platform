from fastapi import FastAPI, Depends, HTTPException, status, Request, Cookie, Form
from fastapi.templating import Jinja2Templates
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.context import CryptContext
from typing import List, Optional
from pydantic import BaseModel
from fastapi.responses import RedirectResponse
from sqlalchemy import DateTime
from datetime import datetime
from fastapi.staticfiles import StaticFiles

# Инициализация приложения и шаблонов
app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Настройка базы данных
Base = declarative_base()
engine = create_engine("sqlite:///app.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Контекст для хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Модели базы данных
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_doctor = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)



class History(Base):
    __tablename__ = "history"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    doctor_id = Column(Integer, ForeignKey("users.id"))
    message = Column(String, nullable=False)
    date = Column(DateTime, default=datetime.utcnow)

    patient = relationship("Patient", back_populates="history")
    doctor = relationship("User")


class Complaint(Base):
    __tablename__ = "complaints"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.now().strftime('%Y-%m-%d %H:%M'))
    patient_id = Column(Integer, ForeignKey("patients.id"))

    patient = relationship("Patient", back_populates="complaints")

class Patient(Base):
    __tablename__ = "patients"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    contact_info = Column(String, nullable=False)
    complaints = Column(String, nullable=True)
    doctor_id = Column(Integer, ForeignKey("users.id"))
    doctor = relationship("User")
    history = relationship("History", back_populates="patient")
    complaints = relationship("Complaint", back_populates="patient")

Base.metadata.create_all(bind=engine)



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def oauth2_scheme(access_token: Optional[str] = Cookie(None)):
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return access_token



def get_user_by_email(db, email):
    return db.query(User).filter(User.email == email).first()

def authenticate_user(db, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user



class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    is_doctor: bool
    is_admin: bool
    verified: bool

    class Config:
        from_attributes = True

class PatientResponse(BaseModel):
    id: int
    name: str
    contact_info: str
    complaints: str
    doctor_id: Optional[int]

    class Config:
        from_attributes = True



@app.get("/")
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/register/")
def get_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register/", response_model=UserResponse)
def register_user(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    is_doctor: bool = Form(False),
    db: SessionLocal = Depends(get_db),
):
    existing_user = get_user_by_email(db, email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    hashed_password = get_password_hash(password)
    is_admin = not db.query(User).first()  # Первый пользователь становится администратором
    user = User(
        name=name, email=email, hashed_password=hashed_password, is_doctor=is_doctor, is_admin=is_admin
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    if not is_doctor and not is_admin:
        patient = Patient(name=name, contact_info=email)
        db.add(patient)
        db.commit()
        # Перенаправление для пациента
        redirect_url = f"/patient/{patient.id}/history"
        response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="access_token", value=user.email, httponly=True)
        return response
    return user

class LoginRequest(BaseModel):
    email: str
    password: str

@app.get("/login/")
def get_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})



@app.post("/login/")
async def login(
    request: Request,
    email: str = Form(...), 
    password: str = Form(...), 
    db: SessionLocal = Depends(get_db)
):
    form_data = await request.form()
    print("Полученные данные формы:", form_data)
    user = authenticate_user(db, email, password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user.is_admin:
        redirect_url = "/admin/dashboard"
    elif user.is_doctor:
        redirect_url = "/doctor/dashboard"
    else:
        patient = db.query(Patient).filter(Patient.name == user.name).first()
        if not patient:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")
        
        # Перенаправление для пациента
        redirect_url = f"/patient/{patient.id}/history"

    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="access_token", value=user.email, httponly=True)
    return response


@app.get("/admin/dashboard/")
def admin_dashboard(
    request: Request, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)
):
    user = get_user_by_email(db, token)
    if not user or not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    doctors = db.query(User).filter(User.is_doctor).all()
    return templates.TemplateResponse("admin_dashboard.html", {"request": request, "doctors": doctors})

@app.post("/admin/verify/")
def approve_doctor(
    email: str = Form(...),  # Теперь данные берутся из тела запроса (формы)
    token: str = Depends(oauth2_scheme),
    db: SessionLocal = Depends(get_db)
):
    user = get_user_by_email(db, token)
    if not user or not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    doctor = get_user_by_email(db, email)
    if not doctor or not doctor.is_doctor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Doctor not found")

    doctor.verified = True
    db.commit()
    return RedirectResponse(url="/admin/dashboard/", status_code=303)

@app.post("/admin/delete/")
def delete_doctor(
    email: str = Form(...),  # Получаем email из формы
    token: str = Depends(oauth2_scheme),
    db: SessionLocal = Depends(get_db)
):
    user = get_user_by_email(db, token)
    if not user or not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    doctor = get_user_by_email(db, email)
    if not doctor or not doctor.is_doctor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Doctor not found")

    db.delete(doctor)
    db.commit()

    # После удаления перенаправляем обратно на ту же страницу для обновления данных
    return RedirectResponse(url="/admin/dashboard/", status_code=303)


@app.get("/doctor/dashboard/")
def doctor_dashboard(
    request: Request, token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)
):
    user = get_user_by_email(db, token)
    if not user or not user.is_doctor or not user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    patients = db.query(Patient).filter((Patient.doctor_id == None) | (Patient.doctor_id == user.id)).all()
    return templates.TemplateResponse("doctor_dashboard.html", {"request": request, "patients": patients})

@app.post("/doctor/assign/")
def assign_patient(
    patient_id: int = Form(...),  # Получение ID пациента из формы
    token: str = Depends(oauth2_scheme),
    db: SessionLocal = Depends(get_db)
):
    user = get_user_by_email(db, token)
    if not user or not user.is_doctor or not user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")

    # Назначаем текущего врача пациенту
    patient.doctor_id = user.id
    db.commit()

    return RedirectResponse(url="/doctor/dashboard/", status_code=303)

@app.get("/patient/{patient_id}/card")
def view_patient_card(
    patient_id: int,
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: SessionLocal = Depends(get_db)
):
    # Проверяем, что пользователь имеет права врача
    user = get_user_by_email(db, token)
    if not user or not user.is_doctor or not user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    # Ищем пациента
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")

    # Получаем жалобы пациента
    complaints = db.query(Complaint).filter(Complaint.patient_id == patient_id).all()

    # Получаем историю болезни пациента (записи врача)
    history_records = db.query(History).filter(History.patient_id == patient_id).all()

    # Передаем данные в шаблон
    return templates.TemplateResponse(
        "patient_card.html",
        {
            "request": request,
            "patient": patient,
            "complaints": complaints,
            "history_records": history_records,
        }
    )


@app.post("/doctor/add_record")
def add_record(
    patient_id: int = Form(...),
    record: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db: SessionLocal = Depends(get_db)
):
    user = get_user_by_email(db, token)
    if not user or not user.is_doctor or not user.verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")

    # Добавление записи в историю болезни 
    new_record = History(
        patient_id=patient_id,
        doctor_id=user.id,
        message=record,
        date=datetime.utcnow()
    )
    db.add(new_record)
    db.commit()

    return RedirectResponse(
        url=f"/patient/{patient_id}/card", status_code=status.HTTP_303_SEE_OTHER
    )

@app.get("/patient/{patient_id}/history/")
def patient_history(
    patient_id: int,
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: SessionLocal = Depends(get_db)
):
    user = get_user_by_email(db, token)
    if not user or user.is_doctor or user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    # Ищем пациента по ID
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient or patient.name != user.name:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")

    # Получаем имя лечащего врача, если он назначен
    doctor_name = patient.doctor.name if patient.doctor else "Не назначен"

    # Получаем жалобы и историю болезней
    complaints = db.query(Complaint).filter(Complaint.patient_id == patient_id).all()
    history_records = db.query(History).filter(History.patient_id == patient_id).order_by(History.date).all()

    # Возвращаем данные в шаблон
    return templates.TemplateResponse(
        "patient_dashboard.html",
        {
            "request": request,
            "doctor_name": doctor_name,
            "patient_id": patient_id,
            "complaints": complaints,
            "history": history_records
        }
    )




@app.post("/patient/{patient_id}/history/")
def add_complaint(
    patient_id: int,
    complaint: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db: SessionLocal = Depends(get_db)
):
    user = get_user_by_email(db, token)
    if not user or user.is_doctor or user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    
    # Проверяем, существует ли пациент
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient or patient.name != user.name:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")
    
    # Создаем новую жалобу с текущей датой и временем
    new_complaint = Complaint(
        content=complaint,
        timestamp=datetime.utcnow(),  # Устанавливаем текущую дату и время в UTC
        patient_id=patient_id
    )
    db.add(new_complaint)
    db.commit()
    db.refresh(new_complaint)
    
    return RedirectResponse(url=f"/patient/{patient.id}/history/", status_code=303)
