# Quick Start Guide - AutoPenTest AI

## Prerequisites

- Docker Desktop (or Docker + Docker Compose)
- Python 3.11+ (for local development)
- Node.js 20+ (for local development)
- Git

## Quick Setup (5 minutes)

### 1. Clone and Navigate
```bash
git clone https://github.com/BitR1ft/FYP.git
cd FYP
```

### 2. Set Up Environment Variables
```bash
cp .env.example .env
# Edit .env if needed (defaults work for development)
```

### 3. Start Databases
```bash
docker-compose up -d
```

This starts:
- PostgreSQL on port 5432
- Neo4j on ports 7474 (HTTP) and 7687 (Bolt)

### 4. Start Backend (Terminal 1)
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the backend
uvicorn app.main:app --reload
```

Backend will be available at: http://localhost:8000
API docs at: http://localhost:8000/docs

### 5. Start Frontend (Terminal 2)
```bash
cd frontend
npm install
npm run dev
```

Frontend will be available at: http://localhost:3000

## First Steps

### 1. Create an Account
1. Open http://localhost:3000
2. Click "Sign Up"
3. Fill in the registration form
4. You'll be redirected to login

### 2. Login
1. Enter your credentials
2. You'll be taken to the dashboard

### 3. Create Your First Project
1. Click "Create Your First Project" or "New Project"
2. Fill in:
   - **Project Name**: e.g., "Test Scan"
   - **Target**: e.g., "example.com"
   - **Description**: Optional
3. Configure settings (all enabled by default except auto-exploit)
4. Click "Create Project"

### 4. View Your Projects
- Click "View Projects" to see all your projects
- You can view, edit, or delete projects

## API Testing

### Using the Interactive Docs
Visit http://localhost:8000/docs for Swagger UI

### Using curl

**Register:**
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser",
    "password": "password123"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

Save the `access_token` from the response.

**Create Project:**
```bash
curl -X POST http://localhost:8000/api/projects \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "name": "My Project",
    "target": "example.com",
    "description": "Test project"
  }'
```

**List Projects:**
```bash
curl -X GET http://localhost:8000/api/projects \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Running Tests

### Backend Tests
```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

Expected output: 4/4 tests passing

## Troubleshooting

### Port Already in Use
If ports 3000, 5432, 7474, or 8000 are in use:
1. Stop the conflicting services
2. Or modify ports in `docker-compose.yml` and `.env`

### Database Connection Issues
```bash
# Check if databases are running
docker-compose ps

# View database logs
docker-compose logs postgres
docker-compose logs neo4j

# Restart databases
docker-compose restart
```

### Frontend Build Errors
```bash
cd frontend
rm -rf node_modules .next
npm install
npm run dev
```

### Backend Import Errors
```bash
cd backend
source venv/bin/activate
pip install --upgrade -r requirements.txt
```

## Development Workflow

### Backend Development
```bash
# The backend runs with auto-reload
# Any changes to .py files will automatically restart the server
cd backend
source venv/bin/activate
uvicorn app.main:app --reload
```

### Frontend Development
```bash
# Next.js has hot-reload by default
# Changes will appear instantly in the browser
cd frontend
npm run dev
```

### Database Management

**PostgreSQL:**
```bash
# Connect to PostgreSQL
docker exec -it autopentestai-postgres psql -U autopentestai

# Inside psql:
\dt        # List tables (once migrations run)
\q         # Quit
```

**Neo4j:**
- Open http://localhost:7474 in browser
- Username: `neo4j`
- Password: (from .env, default: `autopentestai_dev_password`)

## Next Steps

1. ✅ You've completed Month 1 setup!
2. **Month 2** will add:
   - Real database integration (Prisma migrations)
   - Neo4j graph database setup
   - Reconnaissance pipeline
   - Tool integrations

## Useful Commands

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v

# View all logs
docker-compose logs -f

# Backend tests with coverage
cd backend && pytest --cov=app tests/

# Frontend type check
cd frontend && npm run type-check

# Frontend linting
cd frontend && npm run lint
```

## Documentation

- **API Reference**: http://localhost:8000/docs
- **Project README**: [README.md](../README.md)
- **Architecture**: [docs/ARCHITECTURE.md](ARCHITECTURE.md)
- **Contributing**: [CONTRIBUTING.md](../CONTRIBUTING.md)
- **Month 1 Summary**: [docs/MONTH_1_SUMMARY.md](MONTH_1_SUMMARY.md)

## Support

For issues or questions:
1. Check the [CONTRIBUTING.md](../CONTRIBUTING.md) guide
2. Review the [API documentation](http://localhost:8000/docs)
3. Check Docker logs: `docker-compose logs`

---

**Happy Testing! 🚀**

**Remember**: This is a penetration testing framework. Only use it on systems you own or have explicit permission to test.
