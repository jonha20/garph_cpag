from fastapi import APIRouter
import psycopg2
from backend_db import get_db_connection

router = APIRouter()

# 1. Pie chart - ataques por tipo
@router.get("/ataques-por-tipo")
def ataques_por_tipo():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute('SELECT COUNT(*) FROM "alertas_phishing";')
    phishing = cur.fetchone()[0]

    cur.execute('SELECT COUNT(*) FROM "alertas_login_sospechoso";')
    login = cur.fetchone()[0]

    ddos = 0  # placeholder
    fuerza_bruta = 0  # placeholder

    cur.close()
    conn.close()

    return [
        {"name": "Phishing", "value": phishing},
        {"name": "DDoS", "value": ddos},
        {"name": "Fuerza Bruta", "value": fuerza_bruta},
        {"name": "Login Sospechoso", "value": login},
    ]


# 2. Line chart - ataques por día (últimos 7 días)
@router.get("/ataques-por-dia")
def ataques_por_dia():
    conn = get_db_connection()
    cur = conn.cursor()

    query = """
    SELECT DATE(fecha) as dia, COUNT(*)
    FROM (
        SELECT fecha FROM alertas_phishing
        UNION ALL
        SELECT fecha FROM alertas_login_sospechoso
    ) AS ataques
    WHERE fecha >= CURRENT_DATE - INTERVAL '7 days'
    GROUP BY dia
    ORDER BY dia;
    """
    cur.execute(query)
    rows = cur.fetchall()

    cur.close()
    conn.close()

    return [{"fecha": str(r[0]), "total": r[1]} for r in rows]


# 3. Heatmap - ataques por hora
@router.get("/ataques-por-hora")
def ataques_por_hora():
    conn = get_db_connection()
    cur = conn.cursor()

    query = """
    SELECT EXTRACT(HOUR FROM fecha) as hora, COUNT(*)
    FROM (
        SELECT fecha FROM alertas_phishing
        UNION ALL
        SELECT fecha FROM alertas_login_sospechoso
    ) AS ataques
    GROUP BY hora
    ORDER BY hora;
    """
    cur.execute(query)
    rows = cur.fetchall()

    cur.close()
    conn.close()

    return [{"hora": int(r[0]), "total": r[1]} for r in rows]


# 4. KPIs generales
@router.get("/kpis")
def kpis():
    conn = get_db_connection()
    cur = conn.cursor()

    # Total ataques
    cur.execute("""
    SELECT COUNT(*) FROM (
        SELECT fecha FROM alertas_phishing
        UNION ALL
        SELECT fecha FROM alertas_login_sospechoso
    ) AS ataques;
    """)
    total = cur.fetchone()[0]

    # Ataques últimas 24h
    cur.execute("""
    SELECT COUNT(*) FROM (
        SELECT fecha FROM alertas_phishing
        UNION ALL
        SELECT fecha FROM alertas_login_sospechoso
    ) AS ataques
    WHERE fecha >= NOW() - INTERVAL '24 hours';
    """)
    ultimas_24h = cur.fetchone()[0]

    # Usuarios afectados → de momento un número dummy
    usuarios_afectados = 5

    # Tiempo medio resolución → dummy (lo sustituiremos si tienes la columna)
    tiempo_resolucion = "3h 15m"

    cur.close()
    conn.close()

    return {
        "total": total,
        "ultimas_24h": ultimas_24h,
        "usuarios_afectados": usuarios_afectados,
        "tiempo_resolucion": tiempo_resolucion,
    }
