"""Atividade Flask: página pública + áreas restritas (autenticação com hash e SQLite).

Funções: cadastro, login com bloqueio por tentativas, notas (criar/editar/fixar/excluir),
relatório de acessos com gráfico e CSV, troca de senha e edição da página pessoal (admin).
"""
import csv
import hashlib
import hmac
import io
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
# Em um sistema real, defina SECRET_KEY por variável de ambiente (valor longo e aleatório).
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "chave-didatica-troque-depois"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

CAMINHO_BANCO = Path(os.environ.get("DB_PATH", Path(__file__).with_name("app.db")))
ITERACOES = 200_000        # custo do PBKDF2 (hash lento, de propósito)
LIMITE_FALHAS = 5          # tentativas erradas permitidas...
JANELA_SEG = 300           # ...dentro desta janela (segundos)
CATEGORIAS = ["Geral", "Estudo", "Segurança", "Ideias"]


# ---------- Banco de dados ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(CAMINHO_BANCO)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def fechar_db(_erro):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def agora() -> str:
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S")


# ---------- Hash de senha ----------
def gerar_hash(senha: str, salt_hex: str) -> str:
    """PBKDF2-HMAC-SHA256 com salt único por usuário (evolução do SHA-256 puro da aula)."""
    return hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), bytes.fromhex(salt_hex), ITERACOES
    ).hex()


def cadastrar_usuario(db, usuario: str, senha: str, admin: int = 0):
    salt = secrets.token_hex(16)
    db.execute(
        """INSERT INTO usuarios (usuario, salt, senha_hash, admin, criado_em)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(usuario) DO UPDATE SET salt = excluded.salt,
                                              senha_hash = excluded.senha_hash""",
        (usuario, salt, gerar_hash(senha, salt), admin, agora()),
    )


def validar_usuario(usuario: str):
    if not re.fullmatch(r"[a-z0-9_]{3,30}", usuario):
        return "Use de 3 a 30 caracteres: letras minúsculas, números e _."


def validar_senha(senha: str):
    if len(senha) < 8:
        return "A senha precisa ter pelo menos 8 caracteres."
    if len(senha) > 128:
        return "A senha pode ter no máximo 128 caracteres."
    if not (re.search(r"[A-Za-z]", senha) and re.search(r"\d", senha)):
        return "Misture letras e números na senha."


# ---------- Criação e migração do banco ----------
def garantir_coluna(db, tabela, coluna, ddl):
    colunas = [r[1] for r in db.execute(f"PRAGMA table_info({tabela})")]
    if coluna not in colunas:
        db.execute(f"ALTER TABLE {tabela} ADD COLUMN {coluna} {ddl}")
        return True
    return False


def iniciar_banco():
    with sqlite3.connect(CAMINHO_BANCO) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS usuarios (
                usuario TEXT PRIMARY KEY, salt TEXT NOT NULL, senha_hash TEXT NOT NULL,
                admin INTEGER NOT NULL DEFAULT 0, criado_em TEXT);
            CREATE TABLE IF NOT EXISTS perfil (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                nome TEXT NOT NULL, curso TEXT NOT NULL, bio TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS habilidades (
                id INTEGER PRIMARY KEY AUTOINCREMENT, descricao TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS notas (
                id INTEGER PRIMARY KEY AUTOINCREMENT, usuario TEXT NOT NULL,
                titulo TEXT NOT NULL, texto TEXT NOT NULL, criado_em TEXT NOT NULL,
                categoria TEXT NOT NULL DEFAULT 'Geral',
                fixada INTEGER NOT NULL DEFAULT 0, atualizado_em TEXT);
            CREATE TABLE IF NOT EXISTS acessos (
                id INTEGER PRIMARY KEY AUTOINCREMENT, usuario TEXT NOT NULL,
                data_hora TEXT NOT NULL, sucesso INTEGER NOT NULL, ts REAL, ip TEXT);
            CREATE TABLE IF NOT EXISTS config (chave TEXT PRIMARY KEY, valor TEXT NOT NULL);
        """)
        # Bancos criados pela versão anterior recebem as colunas novas.
        garantir_coluna(db, "usuarios", "admin", "INTEGER NOT NULL DEFAULT 0")
        garantir_coluna(db, "usuarios", "criado_em", "TEXT")
        garantir_coluna(db, "notas", "categoria", "TEXT NOT NULL DEFAULT 'Geral'")
        garantir_coluna(db, "notas", "fixada", "INTEGER NOT NULL DEFAULT 0")
        garantir_coluna(db, "notas", "atualizado_em", "TEXT")
        garantir_coluna(db, "acessos", "ts", "REAL")
        garantir_coluna(db, "acessos", "ip", "TEXT")

        if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
            cadastrar_usuario(db, "aluno_exemplo", "Aula@1234", admin=1)  # credencial FICTÍCIA
        if db.execute("SELECT COUNT(*) FROM usuarios WHERE admin = 1").fetchone()[0] == 0:
            db.execute("UPDATE usuarios SET admin = 1 "
                       "WHERE rowid = (SELECT MIN(rowid) FROM usuarios)")
        if db.execute("SELECT COUNT(*) FROM perfil").fetchone()[0] == 0:
            db.execute("INSERT INTO perfil VALUES (1, ?, ?, ?)",
                       ("Seu Nome", "Seu curso",
                        "Entre como administrador e use “Editar página” para mudar este texto."))
            db.executemany("INSERT INTO habilidades (descricao) VALUES (?)",
                           [("Python",), ("SQL",), ("Flask",)])
            db.execute("INSERT INTO notas (usuario, titulo, texto, criado_em, categoria, fixada) "
                       "VALUES (?,?,?,?,?,1)",
                       ("aluno_exemplo", "Hash não é criptografia",
                        "Não existe caminho de volta: o sistema só compara hashes.",
                        agora(), "Segurança"))


# ---------- CSRF, usuário logado e cabeçalhos ----------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def antes_da_requisicao():
    if request.endpoint == "static":
        return
    csrf_token()
    if request.method == "POST":
        enviado = request.form.get("_csrf", "")
        if not hmac.compare_digest(enviado, session["_csrf"]):
            abort(400, "O formulário expirou. Recarregue a página e tente de novo.")
    g.eu = None
    nome = session.get("usuario")
    if nome:
        linha = get_db().execute("SELECT usuario, admin FROM usuarios WHERE usuario = ?",
                                 (nome,)).fetchone()
        if linha:
            g.eu = {"nome": linha["usuario"], "admin": bool(linha["admin"])}
        else:
            session.clear()


@app.after_request
def cabecalhos(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


@app.context_processor
def contexto():
    perfil = get_db().execute("SELECT nome FROM perfil WHERE id = 1").fetchone()
    return {"eu": g.get("eu"), "brand": perfil["nome"] if perfil else "Minha página"}


@app.errorhandler(HTTPException)
def erro_http(e):
    mensagens = {
        400: e.description,
        403: "Esta página é só para administradores.",
        404: "Não encontramos esta página. Confira o endereço ou volte ao início.",
        405: "Esta ação não está disponível por aqui.",
    }
    return render_template("erro.html", codigo=e.code,
                           mensagem=mensagens.get(e.code, e.description)), e.code


def login_required(view):
    @wraps(view)
    def protegida(*args, **kwargs):
        if g.eu is None:
            flash("Entre na sua conta para acessar esta página.", "erro")
            proxima = request.path if request.method == "GET" else None
            return redirect(url_for("login", next=proxima))
        return view(*args, **kwargs)
    return protegida


def admin_required(view):
    @wraps(view)
    def so_admin(*args, **kwargs):
        if not (g.eu and g.eu["admin"]):
            abort(403)
        return view(*args, **kwargs)
    return so_admin


# ---------- Bloqueio por tentativas ----------
def falhas_recentes(db, usuario, ip):
    """Falhas deste usuário+IP na janela, depois do último login bem-sucedido."""
    return db.execute(
        """SELECT ts FROM acessos
           WHERE sucesso = 0 AND usuario = ? AND ip = ? AND ts > ?
             AND ts > COALESCE((SELECT MAX(ts) FROM acessos
                                WHERE sucesso = 1 AND usuario = ? AND ip = ?), 0)
           ORDER BY ts""",
        (usuario, ip, time.time() - JANELA_SEG, usuario, ip)).fetchall()


def segundos_bloqueio(falhas):
    if len(falhas) < LIMITE_FALHAS:
        return 0
    liberar = falhas[-LIMITE_FALHAS]["ts"] + JANELA_SEG
    return max(1, int(liberar - time.time()) + 1)


# ---------- Páginas públicas ----------
@app.route("/")
def index():
    db = get_db()
    if not session.get("contou_visita"):
        db.execute("INSERT INTO config (chave, valor) VALUES ('visitas', '1') "
                   "ON CONFLICT(chave) DO UPDATE SET valor = CAST(valor AS INTEGER) + 1")
        db.commit()
        session["contou_visita"] = True
    visitas = int(db.execute("SELECT valor FROM config WHERE chave = 'visitas'").fetchone()[0])
    perfil = db.execute("SELECT * FROM perfil WHERE id = 1").fetchone()
    habilidades = db.execute("SELECT descricao FROM habilidades ORDER BY id").fetchall()
    n_contas = db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
    n_notas = db.execute("SELECT COUNT(*) FROM notas").fetchone()[0]
    minhas = None
    if g.eu:
        minhas = db.execute("SELECT COUNT(*) FROM notas WHERE usuario = ?",
                            (g.eu["nome"],)).fetchone()[0]
    return render_template("index.html", perfil=perfil, habilidades=habilidades,
                           visitas=visitas, n_contas=n_contas, n_notas=n_notas, minhas=minhas)


# ---------- Autenticação ----------
@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if g.eu:
        return redirect(url_for("notas"))
    usuario = ""
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip().lower()
        senha = request.form.get("senha", "")
        confirma = request.form.get("confirma", "")
        db = get_db()
        erro = validar_usuario(usuario) or validar_senha(senha)
        if not erro and senha != confirma:
            erro = "As duas senhas não são iguais."
        if not erro and db.execute("SELECT 1 FROM usuarios WHERE usuario = ?",
                                   (usuario,)).fetchone():
            erro = "Esse nome de usuário já existe. Escolha outro."
        if erro:
            flash(erro, "erro")
            return render_template("cadastro.html", usuario=usuario), 400
        cadastrar_usuario(db, usuario, senha)
        db.execute("INSERT INTO acessos (usuario, data_hora, sucesso, ts, ip) VALUES (?,?,1,?,?)",
                   (usuario, agora(), time.time(), request.remote_addr or "?"))
        db.commit()
        session.clear()
        session["usuario"] = usuario
        session["_csrf"] = secrets.token_hex(16)
        flash("Conta criada. Bem-vindo(a)!", "ok")
        return redirect(url_for("notas"))
    return render_template("cadastro.html", usuario=usuario)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.eu and request.method == "GET":
        return redirect(url_for("notas"))
    usuario, espera = "", 0
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip().lower()[:50]
        senha = request.form.get("senha", "")
        ip = request.remote_addr or "?"
        db = get_db()

        espera = segundos_bloqueio(falhas_recentes(db, usuario, ip))
        if espera:
            flash(f"Muitas tentativas incorretas. Tente de novo em {espera} segundos.", "erro")
            return render_template("login.html", usuario=usuario, bloqueio=espera), 429

        reg = db.execute("SELECT salt, senha_hash FROM usuarios WHERE usuario = ?",
                         (usuario,)).fetchone()
        if reg is None:  # calcula mesmo assim: o tempo não revela se o usuário existe
            gerar_hash(senha[:128], "00" * 16)
            ok = False
        else:
            ok = len(senha) <= 128 and hmac.compare_digest(
                gerar_hash(senha, reg["salt"]), reg["senha_hash"])

        db.execute("INSERT INTO acessos (usuario, data_hora, sucesso, ts, ip) VALUES (?,?,?,?,?)",
                   (usuario, agora(), int(ok), time.time(), ip))
        db.commit()

        if ok:
            session.clear()
            session["usuario"] = usuario
            session["_csrf"] = secrets.token_hex(16)
            flash(f"Olá, {usuario}! Login feito com sucesso.", "ok")
            destino = request.args.get("next", "")
            if not destino.startswith("/") or destino.startswith("//") or "\\" in destino:
                destino = url_for("notas")
            return redirect(destino)

        falhas = falhas_recentes(db, usuario, ip)
        espera = segundos_bloqueio(falhas)
        if espera:
            flash(f"Muitas tentativas incorretas. Tente de novo em {espera} segundos.", "erro")
        else:
            restam = LIMITE_FALHAS - len(falhas)
            flash(f"Usuário ou senha incorretos. Você ainda tem {restam} tentativa(s).", "erro")
        return render_template("login.html", usuario=usuario, bloqueio=espera), \
            (429 if espera else 401)
    return render_template("login.html", usuario=usuario, bloqueio=0)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Você saiu da conta.", "ok")
    return redirect(url_for("index"))


# ---------- Restrita 1: notas ----------
def ler_nota_form():
    titulo = request.form.get("titulo", "").strip()
    texto = request.form.get("texto", "").strip()
    categoria = request.form.get("categoria", "Geral")
    if categoria not in CATEGORIAS:
        categoria = "Geral"
    erro = None
    if not titulo or not texto:
        erro = "Preencha o título e o texto da nota."
    elif len(titulo) > 80 or len(texto) > 2000:
        erro = "Título: até 80 caracteres. Texto: até 2000."
    return titulo, texto, categoria, erro


@app.route("/notas")
@login_required
def notas():
    db = get_db()
    nome = g.eu["nome"]
    cat = request.args.get("cat", "")
    sql, params = "SELECT * FROM notas WHERE usuario = ?", [nome]
    if cat in CATEGORIAS:
        sql += " AND categoria = ?"
        params.append(cat)
    lista = db.execute(sql + " ORDER BY fixada DESC, id DESC", params).fetchall()
    contagem = {r["categoria"]: r["n"] for r in db.execute(
        "SELECT categoria, COUNT(*) AS n FROM notas WHERE usuario = ? GROUP BY categoria",
        (nome,))}
    return render_template("notas.html", notas=lista, cat=cat, categorias=CATEGORIAS,
                           contagem=contagem, total=sum(contagem.values()))


@app.route("/notas/nova", methods=["POST"])
@login_required
def nota_nova():
    titulo, texto, categoria, erro = ler_nota_form()
    if erro:
        flash(erro, "erro")
    else:
        db = get_db()
        db.execute("INSERT INTO notas (usuario, titulo, texto, criado_em, categoria) "
                   "VALUES (?,?,?,?,?)", (g.eu["nome"], titulo, texto, agora(), categoria))
        db.commit()
        flash("Nota salva.", "ok")
    return redirect(url_for("notas"))


def buscar_nota(nota_id):
    nota = get_db().execute("SELECT * FROM notas WHERE id = ? AND usuario = ?",
                            (nota_id, g.eu["nome"])).fetchone()
    if nota is None:
        abort(404)
    return nota


@app.route("/notas/<int:nota_id>/editar", methods=["GET", "POST"])
@login_required
def nota_editar(nota_id):
    nota = buscar_nota(nota_id)
    if request.method == "POST":
        titulo, texto, categoria, erro = ler_nota_form()
        if erro:
            flash(erro, "erro")
        else:
            db = get_db()
            db.execute("UPDATE notas SET titulo=?, texto=?, categoria=?, atualizado_em=? "
                       "WHERE id=? AND usuario=?",
                       (titulo, texto, categoria, agora(), nota_id, g.eu["nome"]))
            db.commit()
            flash("Alterações salvas.", "ok")
            return redirect(url_for("notas"))
    return render_template("nota_editar.html", nota=nota, categorias=CATEGORIAS)


@app.route("/notas/<int:nota_id>/fixar", methods=["POST"])
@login_required
def nota_fixar(nota_id):
    buscar_nota(nota_id)
    db = get_db()
    db.execute("UPDATE notas SET fixada = 1 - fixada WHERE id = ? AND usuario = ?",
               (nota_id, g.eu["nome"]))
    db.commit()
    return redirect(url_for("notas"))


@app.route("/notas/<int:nota_id>/excluir", methods=["POST"])
@login_required
def nota_excluir(nota_id):
    buscar_nota(nota_id)
    db = get_db()
    db.execute("DELETE FROM notas WHERE id = ? AND usuario = ?", (nota_id, g.eu["nome"]))
    db.commit()
    flash("Nota excluída.", "ok")
    return redirect(url_for("notas"))


# ---------- Restrita 2: relatório de acessos ----------
def consulta_acessos(db, filtro=None, limite=None):
    cond, params = [], []
    if not g.eu["admin"]:
        cond.append("usuario = ?")
        params.append(g.eu["nome"])
    if filtro == "falhas":
        cond.append("sucesso = 0")
    elif filtro == "sucessos":
        cond.append("sucesso = 1")
    sql = "SELECT usuario, data_hora, sucesso, ip FROM acessos"
    if cond:
        sql += " WHERE " + " AND ".join(cond)
    sql += " ORDER BY id DESC"
    if limite:
        sql += f" LIMIT {int(limite)}"
    return db.execute(sql, params).fetchall()


@app.route("/acessos")
@login_required
def acessos():
    db = get_db()
    filtro = request.args.get("filtro", "todos")
    if filtro not in ("todos", "falhas", "sucessos"):
        filtro = "todos"
    todos = consulta_acessos(db, limite=5000)
    total = len(todos)
    falhas = sum(1 for r in todos if not r["sucesso"])

    hoje = datetime.now().date()
    dias = [hoje - timedelta(days=i) for i in range(6, -1, -1)]
    cont = {d: [0, 0] for d in dias}  # [sucessos, falhas]
    for r in todos:
        try:
            d = datetime.strptime(r["data_hora"], "%d/%m/%Y %H:%M:%S").date()
        except ValueError:
            continue
        if d in cont:
            cont[d][0 if r["sucesso"] else 1] += 1
    maximo = max([a + b for a, b in cont.values()] + [1])
    grafico = [{"rotulo": d.strftime("%d/%m"), "ok": a, "falha": b,
                "h_ok": round(a / maximo * 100), "h_falha": round(b / maximo * 100)}
               for d, (a, b) in cont.items()]

    registros = consulta_acessos(db, filtro=filtro, limite=50)
    return render_template("acessos.html", registros=registros, total=total, falhas=falhas,
                           grafico=grafico, filtro=filtro)


@app.route("/acessos.csv")
@login_required
def acessos_csv():
    def seguro(valor):  # evita que o Excel execute células iniciadas por = + - @
        valor = str(valor or "")
        return "'" + valor if valor[:1] in "=+-@" else valor

    saida = io.StringIO()
    escritor = csv.writer(saida)
    escritor.writerow(["usuario", "data_hora", "resultado", "ip"])
    for r in consulta_acessos(get_db()):
        escritor.writerow([seguro(r["usuario"]), r["data_hora"],
                           "sucesso" if r["sucesso"] else "falha",
                           seguro(r["ip"]) if g.eu["admin"] else ""])
    return Response("\ufeff" + saida.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=acessos.csv"})


# ---------- Conta (troca de senha) ----------
@app.route("/conta", methods=["GET", "POST"])
@login_required
def conta():
    db = get_db()
    nome = g.eu["nome"]
    if request.method == "POST":
        atual = request.form.get("atual", "")
        nova = request.form.get("nova", "")
        confirma = request.form.get("confirma", "")
        reg = db.execute("SELECT salt, senha_hash FROM usuarios WHERE usuario = ?",
                         (nome,)).fetchone()
        erro = None
        if len(atual) > 128 or not hmac.compare_digest(
                gerar_hash(atual, reg["salt"]), reg["senha_hash"]):
            erro = "A senha atual está incorreta."
        else:
            erro = validar_senha(nova)
            if not erro and nova != confirma:
                erro = "As duas senhas novas não são iguais."
            if not erro and nova == atual:
                erro = "Escolha uma senha diferente da atual."
        if erro:
            flash(erro, "erro")
        else:
            novo_salt = secrets.token_hex(16)  # novo salt a cada troca
            db.execute("UPDATE usuarios SET salt = ?, senha_hash = ? WHERE usuario = ?",
                       (novo_salt, gerar_hash(nova, novo_salt), nome))
            db.commit()
            flash("Senha alterada.", "ok")
            return redirect(url_for("conta"))
    info = db.execute("SELECT criado_em FROM usuarios WHERE usuario = ?", (nome,)).fetchone()
    anterior = db.execute("SELECT data_hora FROM acessos WHERE usuario = ? AND sucesso = 1 "
                          "ORDER BY id DESC LIMIT 1 OFFSET 1", (nome,)).fetchone()
    n_notas = db.execute("SELECT COUNT(*) FROM notas WHERE usuario = ?", (nome,)).fetchone()[0]
    return render_template("conta.html", criado_em=info["criado_em"] if info else None,
                           anterior=anterior["data_hora"] if anterior else None, n_notas=n_notas)


# ---------- Administração da página pessoal ----------
@app.route("/perfil/editar", methods=["GET", "POST"])
@login_required
@admin_required
def perfil_editar():
    db = get_db()
    if request.method == "POST":
        acao = request.form.get("acao")
        if acao == "salvar":
            nome = request.form.get("nome", "").strip()
            curso = request.form.get("curso", "").strip()
            bio = request.form.get("bio", "").strip()
            if not (nome and curso and bio) or len(nome) > 60 or len(curso) > 80 or len(bio) > 600:
                flash("Preencha os três campos (nome até 60, curso até 80, bio até 600).", "erro")
            else:
                db.execute("UPDATE perfil SET nome=?, curso=?, bio=? WHERE id=1",
                           (nome, curso, bio))
                db.commit()
                flash("Página atualizada.", "ok")
        elif acao == "habilidade":
            desc = request.form.get("descricao", "").strip()
            if not desc or len(desc) > 40:
                flash("Escreva uma habilidade com até 40 caracteres.", "erro")
            else:
                db.execute("INSERT INTO habilidades (descricao) VALUES (?)", (desc,))
                db.commit()
                flash("Habilidade adicionada.", "ok")
        return redirect(url_for("perfil_editar"))
    perfil = db.execute("SELECT * FROM perfil WHERE id = 1").fetchone()
    habilidades = db.execute("SELECT id, descricao FROM habilidades ORDER BY id").fetchall()
    return render_template("perfil_editar.html", perfil=perfil, habilidades=habilidades)


@app.route("/habilidades/<int:hab_id>/excluir", methods=["POST"])
@login_required
@admin_required
def habilidade_excluir(hab_id):
    db = get_db()
    db.execute("DELETE FROM habilidades WHERE id = ?", (hab_id,))
    db.commit()
    flash("Habilidade removida.", "ok")
    return redirect(url_for("perfil_editar"))


iniciar_banco()

if __name__ == "__main__":
    app.run(debug=True)
