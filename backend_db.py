import psycopg2

def get_db_connection():
    return psycopg2.connect(
        host="dpg-d36ihvadbo4c73drlcng-a.frankfurt-postgres.render.com",
        database="tripulacionchallenge",
        user="tripulacionchallenge_user",
        password="vHIZ4gyELvJdH48Qc00YTcEeAElk7wsL",
        port=5432
    )
    return conn
