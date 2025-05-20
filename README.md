# Health-Platform 🏥

Веб-приложение для управления медицинской информацией, разработанное с использованием FastAPI и SQLite.

## 🚀 Возможности

- Роли: **Администратор**, **Врач**, **Пациент**
- Регистрация и вход в систему
- Просмотр и редактирование карты пациента
- Добавление жалоб и истории болезни
- Визуализация через HTML (Jinja2-шаблоны)

## 🛠️ Технологии

- **FastAPI** — современный и быстрый backend-фреймворк
- **SQLite + SQLAlchemy** — встроенная база данных и ORM
- **Jinja2** — шаблоны для HTML-интерфейса
- **Pydantic** — проверка и сериализация данных
- **Uvicorn** — ASGI-сервер

## ⚙️ Установка и запуск

```bash
git clone https://github.com/yourusername/health-platform.git
cd health-platform
pip install -r requirements.txt
uvicorn main:app --reload
