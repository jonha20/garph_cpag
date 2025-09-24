from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend_db import get_db_connection

app = FastAPI()

# ==========================
#   CONFIGURAR CORS
# ==========================
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "https://proyecto-final-tripulaciones-f-s-bpzh.onrender.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
#   ENDPOINTS
# ==========================

# 📊 Ataques por tipo
@app.get("/ataques-por-tipo")
def ataques_por_tipo():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT ta.descripcion, COUNT(*) 
        FROM (
            SELECT id_tipo FROM public.alertas_phishing
            UNION ALL
            SELECT id_tipo FROM public.alertas_fuerza_bruta
            UNION ALL
            SELECT id_tipo FROM public.alertas_dos
            UNION ALL
            SELECT id_tipo FROM public.alertas_ddos
            UNION ALL
            SELECT id_tipo FROM public.alertas_login_sospechoso
        ) a
        JOIN public.tipos_ataques ta ON a.id_tipo = ta.id_tipo
        GROUP BY ta.descripcion
        ORDER BY COUNT(*) DESC;
    """)
    rows = cur.fetchall()

    cur.close()
    conn.close()
    return [{"name": r[0], "value": r[1]} for r in rows]


# ⏰ Ataques por hora
@app.get("/ataques-por-hora")
def ataques_por_hora():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT h, COUNT(*) 
        FROM (
            SELECT EXTRACT(HOUR FROM hora) AS h FROM public.alertas_phishing
            UNION ALL
            SELECT EXTRACT(HOUR FROM hora) FROM public.alertas_fuerza_bruta
            UNION ALL
            SELECT EXTRACT(HOUR FROM hora) FROM public.alertas_dos
            UNION ALL
            SELECT EXTRACT(HOUR FROM hora) FROM public.alertas_ddos
            UNION ALL
            SELECT EXTRACT(HOUR FROM hora) FROM public.alertas_login_sospechoso
        ) AS horas
        GROUP BY h
        ORDER BY h;
    """)
    rows = cur.fetchall()

    cur.close()
    conn.close()
    return [{"hour": int(r[0]), "count": r[1]} for r in rows if r[0] is not None]


# 📅 Ataques por día
@app.get("/ataques-por-dia")
def ataques_por_dia():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT fecha, COUNT(*) 
        FROM (
            SELECT fecha FROM public.alertas_phishing
            UNION ALL
            SELECT fecha FROM public.alertas_fuerza_bruta
            UNION ALL
            SELECT fecha FROM public.alertas_dos
            UNION ALL
            SELECT fecha FROM public.alertas_ddos
            UNION ALL
            SELECT fecha FROM public.alertas_login_sospechoso
        ) AS fechas
        GROUP BY fecha
        ORDER BY fecha;
    """)
    rows = cur.fetchall()

    cur.close()
    conn.close()
    return [{"date": str(r[0]), "count": r[1]} for r in rows]


# 🌍 Mapa por país
@app.get("/ataques-por-pais")
def ataques_por_pais():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT country, COUNT(*)
        FROM (
            SELECT codigo_pais AS country FROM public.alertas_fuerza_bruta WHERE codigo_pais IS NOT NULL
            UNION ALL
            SELECT codigo_pais FROM public.alertas_dos WHERE codigo_pais IS NOT NULL
            UNION ALL
            SELECT codigo_pais FROM public.alertas_ddos WHERE codigo_pais IS NOT NULL
            UNION ALL
            SELECT pais FROM public.alertas_login_sospechoso WHERE pais IS NOT NULL
        ) p
        GROUP BY country
        ORDER BY COUNT(*) DESC;
    """)
    rows = cur.fetchall()

    cur.close()
    conn.close()
    return [{"country": r[0], "count": r[1]} for r in rows]


# ⚡ KPIs principales
@app.get("/kpis")
def kpis():
    conn = get_db_connection()
    cur = conn.cursor()

    # Total alertas
    cur.execute("""
        SELECT COUNT(*) FROM (
            SELECT id FROM public.alertas_phishing
            UNION ALL
            SELECT id FROM public.alertas_fuerza_bruta
            UNION ALL
            SELECT id FROM public.alertas_dos
            UNION ALL
            SELECT id FROM public.alertas_ddos
            UNION ALL
            SELECT id FROM public.alertas_login_sospechoso
        ) AS todas;
    """)
    total_alertas = cur.fetchone()[0]

    # Últimas 24 horas (reales)
    cur.execute("""
        SELECT COUNT(*) FROM (
            SELECT fecha, hora FROM public.alertas_phishing
            UNION ALL
            SELECT fecha, hora FROM public.alertas_fuerza_bruta
            UNION ALL
            SELECT fecha, hora FROM public.alertas_dos
            UNION ALL
            SELECT fecha, hora FROM public.alertas_ddos
            UNION ALL
            SELECT fecha, hora FROM public.alertas_login_sospechoso
        ) a
        WHERE (CAST(fecha AS timestamp) + hora) >= NOW() - INTERVAL '24 hours';
    """)
    ultimas_24h = cur.fetchone()[0]

    # Media de severidad → solo palabra
    cur.execute("""
        SELECT AVG(
          CASE 
            WHEN UPPER(riesgo) = 'BAJO' THEN 1
            WHEN UPPER(riesgo) = 'MEDIO' THEN 2
            WHEN UPPER(riesgo) = 'ALTO' THEN 3
            WHEN UPPER(riesgo) IN ('CRÍTICO','CRITICO','CRÍTICA','CRITICA') THEN 4
            ELSE NULL
          END
        )
        FROM (
            SELECT riesgo FROM public.alertas_phishing
            UNION ALL
            SELECT riesgo FROM public.alertas_fuerza_bruta
            UNION ALL
            SELECT riesgo FROM public.alertas_dos
            UNION ALL
            SELECT riesgo FROM public.alertas_ddos
            UNION ALL
            SELECT riesgo FROM public.alertas_login_sospechoso
        ) AS riesgos;
    """)
    media_riesgo = cur.fetchone()[0] or 0

    if media_riesgo < 1.5:
        nivel_riesgo = "BAJO"
    elif media_riesgo < 2.5:
        nivel_riesgo = "MEDIO"
    elif media_riesgo < 3.5:
        nivel_riesgo = "ALTO"
    else:
        nivel_riesgo = "CRÍTICO"

    # Clientes afectados
    cur.execute("""
        SELECT COUNT(DISTINCT id_cliente) FROM (
            SELECT id_cliente FROM public.alertas_phishing
            UNION ALL
            SELECT id_cliente FROM public.alertas_fuerza_bruta
            UNION ALL
            SELECT id_cliente FROM public.alertas_dos
            UNION ALL
            SELECT id_cliente FROM public.alertas_ddos
            UNION ALL
            SELECT id_cliente FROM public.alertas_login_sospechoso
        ) AS clientes;
    """)
    clientes_afectados = cur.fetchone()[0]

    cur.close()
    conn.close()

    return {
        "total_alertas": total_alertas,
        "ultimas_24h": ultimas_24h,
        "nivel_riesgo": nivel_riesgo,   
        "clientes_afectados": clientes_afectados,
        
    }


# 📊 Ataques últimos 7 días (reales)
@app.get("/ataques-ultimos-7-dias")
def ataques_ultimos_7_dias():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT fecha, COUNT(*) 
        FROM (
            SELECT fecha, hora FROM public.alertas_phishing
            UNION ALL
            SELECT fecha, hora FROM public.alertas_fuerza_bruta
            UNION ALL
            SELECT fecha, hora FROM public.alertas_dos
            UNION ALL
            SELECT fecha, hora FROM public.alertas_ddos
            UNION ALL
            SELECT fecha, hora FROM public.alertas_login_sospechoso
        ) a
        WHERE (CAST(fecha AS timestamp) + hora) >= NOW() - INTERVAL '7 days'
        GROUP BY fecha
        ORDER BY fecha;
    """)
    rows = cur.fetchall()

    cur.close()
    conn.close()

    return [{"fecha": str(r[0]), "total": r[1]} for r in rows]


# ⏱️ Ataques últimas 24h (reales por hora)
@app.get("/ataques-ultimas-24h")
def ataques_ultimas_24h():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT h, COUNT(*) 
        FROM (
            SELECT EXTRACT(HOUR FROM hora) AS h, fecha, hora FROM public.alertas_phishing
            UNION ALL
            SELECT EXTRACT(HOUR FROM hora), fecha, hora FROM public.alertas_fuerza_bruta
            UNION ALL
            SELECT EXTRACT(HOUR FROM hora), fecha, hora FROM public.alertas_dos
            UNION ALL
            SELECT EXTRACT(HOUR FROM hora), fecha, hora FROM public.alertas_ddos
            UNION ALL
            SELECT EXTRACT(HOUR FROM hora), fecha, hora FROM public.alertas_login_sospechoso
        ) a
        WHERE (CAST(fecha AS timestamp) + hora) >= NOW() - INTERVAL '24 hours'
        GROUP BY h
        ORDER BY h;
    """)
    rows = cur.fetchall()

    cur.close()
    conn.close()

    return [{"hora": f"{int(r[0]):02d}:00", "total": r[1]} for r in rows if r[0] is not None]


# 🔝 Top 10 IPs
@app.get("/top-ips")
def top_ips():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT ip, COUNT(*) AS total
        FROM (
            SELECT ip FROM public.alertas_fuerza_bruta
            UNION ALL
            SELECT ip FROM public.alertas_login_sospechoso
            UNION ALL
            SELECT ip FROM public.alertas_dos
            UNION ALL
            SELECT ip FROM public.alertas_ddos
            UNION ALL
            SELECT ip FROM public.alertas_phishing
        ) AS todas_ips
        WHERE ip IS NOT NULL
        GROUP BY ip
        ORDER BY total DESC
        LIMIT 10;
    """)
    rows = cur.fetchall()

    cur.close()
    conn.close()
    return [{"ip": r[0], "count": r[1]} for r in rows]
