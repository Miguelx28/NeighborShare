// Mock del módulo db antes de importar cualquier ruta
const mockRequest = {
    input: jest.fn().mockReturnThis(),
    query: jest.fn(),
};
const mockPool = { request: jest.fn(() => mockRequest) };

jest.mock('../db', () => ({
    poolPromise: Promise.resolve(mockPool),
    sql: { VarChar: 'VarChar', Int: 'Int', Bit: 'Bit' },
}));

const request = require('supertest');
const express = require('express');
const authRoutes = require('../routes/auth');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// App mínima para testear solo las rutas de auth
const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);

process.env.JWT_SECRET = 'secret_de_prueba';

beforeEach(() => {
    jest.clearAllMocks();
    mockPool.request.mockReturnValue(mockRequest);
    mockRequest.input.mockReturnThis();
});

// ─────────────────────────────────────────────
// Registrar
// ─────────────────────────────────────────────

describe('POST /api/auth/register', () => {

    test(' Registra un usuario nuevo correctamente', async () => {
        mockRequest.query
            .mockResolvedValueOnce({ recordset: [] })
            .mockResolvedValueOnce({ recordset: [{ id_usuario: 1 }] });

        const res = await request(app)
            .post('/api/auth/register')
            .send({ nombre: 'Ana', email: 'ana@mail.com', password: '1234' });

        expect(res.statusCode).toBe(201);
        expect(res.body).toHaveProperty('token');
        expect(res.body.user).toMatchObject({ nombre: 'Ana', email: 'ana@mail.com' });
    });

    test(' Falla si faltan campos obligatorios', async () => {
        const res = await request(app)
            .post('/api/auth/register')
            .send({ email: 'ana@mail.com' });

        expect(res.statusCode).toBe(400);
        expect(res.body.error).toMatch(/ingrese todos los campos/i);
    });

    test(' Falla si el usuario ya existe', async () => {
        mockRequest.query.mockResolvedValueOnce({
            recordset: [{ id_usuario: 99, email: 'ana@mail.com' }]
        });

        const res = await request(app)
            .post('/api/auth/register')
            .send({ nombre: 'Ana', email: 'ana@mail.com', password: '1234' });

        expect(res.statusCode).toBe(400);
        expect(res.body.error).toMatch(/ya existe/i);
    });

    test(' Falla si ocurre un error en el servidor', async () => {
        mockRequest.query.mockRejectedValueOnce(new Error('DB caída'));

        const res = await request(app)
            .post('/api/auth/register')
            .send({ nombre: 'Ana', email: 'ana@mail.com', password: '1234' });

        expect(res.statusCode).toBe(500);
        expect(res.body.error).toMatch(/error en el servidor/i);
    });

    test(' La contraseña se guarda encriptada (no en texto plano)', async () => {
        mockRequest.query
            .mockResolvedValueOnce({ recordset: [] })
            .mockResolvedValueOnce({ recordset: [{ id_usuario: 1 }] });

        const hashSpy = jest.spyOn(bcrypt, 'hash');

        await request(app)
            .post('/api/auth/register')
            .send({ nombre: 'Ana', email: 'ana@mail.com', password: 'miPassword' });

        expect(hashSpy).toHaveBeenCalledWith('miPassword', expect.any(String));
    });

    test(' El token JWT devuelto es válido y contiene el id del usuario', async () => {
        mockRequest.query
            .mockResolvedValueOnce({ recordset: [] })
            .mockResolvedValueOnce({ recordset: [{ id_usuario: 42 }] });

        const res = await request(app)
            .post('/api/auth/register')
            .send({ nombre: 'Ana', email: 'ana@mail.com', password: '1234' });

        expect(res.statusCode).toBe(201);
        const decoded = jwt.verify(res.body.token, 'secret_de_prueba');
        expect(decoded.user.id).toBe(42);
    });
});

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────

describe('POST /api/auth/login', () => {

    test(' Login correcto con credenciales válidas', async () => {
        const passwordHash = await bcrypt.hash('1234', 10);

        mockRequest.query.mockResolvedValueOnce({
            recordset: [{
                id_usuario: 1,
                nombre: 'Ana',
                email: 'ana@mail.com',
                password_hash: passwordHash
            }]
        });

        const res = await request(app)
            .post('/api/auth/login')
            .send({ email: 'ana@mail.com', password: '1234' });

        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty('token');
        expect(res.body.user.nombre).toBe('Ana');
    });

    test(' Falla si faltan campos', async () => {
        const res = await request(app)
            .post('/api/auth/login')
            .send({ email: 'ana@mail.com' });

        expect(res.statusCode).toBe(400);
        expect(res.body.error).toMatch(/ingrese todos los campos/i);
    });

    test(' Falla si el usuario no existe', async () => {
        mockRequest.query.mockResolvedValueOnce({ recordset: [] });

        const res = await request(app)
            .post('/api/auth/login')
            .send({ email: 'noexiste@mail.com', password: '1234' });

        expect(res.statusCode).toBe(400);
        expect(res.body.error).toMatch(/no encontrado/i);
    });

    test(' Falla si la contraseña es incorrecta', async () => {
        const passwordHash = await bcrypt.hash('correcta', 10);

        mockRequest.query.mockResolvedValueOnce({
            recordset: [{
                id_usuario: 1,
                nombre: 'Ana',
                email: 'ana@mail.com',
                password_hash: passwordHash
            }]
        });

        const res = await request(app)
            .post('/api/auth/login')
            .send({ email: 'ana@mail.com', password: 'incorrecta' });

        expect(res.statusCode).toBe(400);
        expect(res.body.error).toMatch(/contraseña incorrecta/i);
    });

    test(' Falla si ocurre un error en el servidor', async () => {
        mockRequest.query.mockRejectedValueOnce(new Error('DB caída'));

        const res = await request(app)
            .post('/api/auth/login')
            .send({ email: 'ana@mail.com', password: '1234' });

        expect(res.statusCode).toBe(500);
        expect(res.body.error).toMatch(/error en el servidor/i);
    });

    test(' El token devuelto en login contiene el id del usuario', async () => {
        const passwordHash = await bcrypt.hash('1234', 10);

        mockRequest.query.mockResolvedValueOnce({
            recordset: [{
                id_usuario: 7,
                nombre: 'Ana',
                email: 'ana@mail.com',
                password_hash: passwordHash
            }]
        });

        const res = await request(app)
            .post('/api/auth/login')
            .send({ email: 'ana@mail.com', password: '1234' });

        expect(res.statusCode).toBe(200);
        const decoded = jwt.verify(res.body.token, 'secret_de_prueba');
        expect(decoded.user.id).toBe(7);
    });
});