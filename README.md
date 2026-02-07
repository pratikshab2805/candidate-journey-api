# Candidate Journey Management API

FastAPI-based backend for managing candidate applications, recruitment stages, and role-based access control.

---

## Features

- Candidate CRUD operations
- Fixed hiring pipeline:
  APPLIED → SCREENING → INTERVIEW → HIRED / REJECTED
- Role-Based Access Control
  - Recruiter: full access
  - Candidate: view own status only
- JWT authentication
- Swagger API documentation

---

## Tech Stack

- Python
- FastAPI
- SQLAlchemy
- SQLite
- JWT Authentication

---

## How to Run the Project

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

---

## API Documentation

Once the server is running, open:

```
http://localhost:8000/docs
```

---

## Roles & Permissions

### Recruiter
- Create, update, delete candidates
- Move candidates through hiring stages
- Reject candidates
- View all candidates

### Candidate
- View own profile
- View current hiring status

---

## Hiring Pipeline

APPLIED → SCREENING → INTERVIEW → HIRED  
                     ↘ REJECTED

---

## Database Schema

Users  
- id  
- name  
- email  
- password  
- role  

Candidates  
- id  
- name  
- email  
- role_applied  
- resume_text  
- stage  
- user_id (FK → users.id)

---

## Author

GitHub: https://github.com/pratikshab2805/candidate-journey-api
