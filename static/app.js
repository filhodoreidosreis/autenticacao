"use strict";

/* Tema claro/escuro */
const botaoTema = document.getElementById("tema");
if (botaoTema) {
  botaoTema.addEventListener("click", () => {
    const novo = document.documentElement.dataset.tema === "escuro" ? "claro" : "escuro";
    document.documentElement.dataset.tema = novo;
    try { localStorage.setItem("tema", novo); } catch (e) {}
  });
}

/* Avisos: fecham sozinhos (erros ficam mais tempo) */
document.querySelectorAll(".toast").forEach((t) => {
  const fechar = () => { t.classList.add("saindo"); setTimeout(() => t.remove(), 300); };
  t.querySelector("button").addEventListener("click", fechar);
  setTimeout(fechar, t.classList.contains("erro") ? 9000 : 5000);
});

/* Mostrar/ocultar senha */
document.querySelectorAll("[data-mostrar]").forEach((b) => {
  b.addEventListener("click", () => {
    const campo = b.parentElement.querySelector("input");
    const visivel = campo.type === "text";
    campo.type = visivel ? "password" : "text";
    b.textContent = visivel ? "Mostrar" : "Ocultar";
    b.setAttribute("aria-pressed", String(!visivel));
  });
});

/* Medidor de força + hash SHA-256 ao vivo (efeito avalanche) */
const codificador = new TextEncoder();
async function sha256Hex(texto) {
  const buf = await crypto.subtle.digest("SHA-256", codificador.encode(texto));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function pontuar(s) {
  const pts = [s.length >= 8, s.length >= 12, /[a-z]/.test(s) && /[A-Z]/.test(s), /\d/.test(s), /[^A-Za-z0-9]/.test(s)]
    .filter(Boolean).length;
  return s ? Math.max(1, Math.min(4, pts)) : 0;
}
const ROTULOS = ["Use 8 ou mais caracteres, com letras e números.", "Senha fraca.", "Senha razoável.", "Senha boa.", "Senha forte."];

document.querySelectorAll("[data-medidor]").forEach((campo) => {
  const form = campo.closest("form");
  const caixa = form.querySelector("[data-medidor-box]");
  const texto = form.querySelector("[data-medidor-texto]");
  const demo = form.querySelector("[data-hash-demo]");
  const saida = form.querySelector("[data-hash-saida]");
  const info = form.querySelector("[data-hash-info]");
  const temCrypto = !!(window.crypto && crypto.subtle);
  if (demo && temCrypto) demo.hidden = false;
  let anterior = "", ultimo = 0;

  campo.addEventListener("input", async () => {
    const nivel = pontuar(campo.value);
    caixa.dataset.nivel = nivel;
    texto.textContent = ROTULOS[nivel];
    if (!demo || !temCrypto) return;
    const eu = ++ultimo;
    if (!campo.value) { saida.textContent = "—"; info.textContent = ""; anterior = ""; return; }
    const hash = await sha256Hex(campo.value);
    if (eu !== ultimo) return;
    saida.textContent = "";
    let mudaram = 0;
    [...hash].forEach((ch, i) => {
      const span = document.createElement("span");
      span.textContent = ch;
      if (anterior && anterior[i] !== ch) { span.className = "mudou"; mudaram++; }
      saida.appendChild(span);
    });
    info.textContent = anterior ? `${mudaram} de 64 símbolos mudaram em relação ao hash anterior.` : "";
    anterior = hash;
  });
});

/* Contador de caracteres */
document.querySelectorAll("[data-max]").forEach((el) => {
  const max = Number(el.dataset.max);
  const c = document.createElement("span");
  c.className = "contador";
  el.insertAdjacentElement("afterend", c);
  const atualizar = () => {
    c.textContent = `${el.value.length}/${max}`;
    c.classList.toggle("alerta", el.value.length >= max * 0.9);
  };
  el.addEventListener("input", atualizar);
  atualizar();
});

/* Busca ao vivo nas notas */
const busca = document.getElementById("busca");
if (busca) {
  const cartoes = [...document.querySelectorAll(".nota")];
  const contagem = document.getElementById("contagem");
  const semResultado = document.getElementById("sem-resultado");
  const filtrar = () => {
    const q = busca.value.trim().toLowerCase();
    let n = 0;
    cartoes.forEach((c) => {
      const ok = !q || c.dataset.busca.includes(q);
      c.hidden = !ok;
      if (ok) n++;
    });
    contagem.textContent = cartoes.length ? `${n} de ${cartoes.length}` : "";
    semResultado.hidden = n !== 0 || cartoes.length === 0;
  };
  busca.addEventListener("input", filtrar);
  document.addEventListener("keydown", (e) => {
    const tag = document.activeElement.tagName;
    if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(tag)) { e.preventDefault(); busca.focus(); }
    if (e.key === "Escape" && document.activeElement === busca) { busca.value = ""; filtrar(); }
  });
  filtrar();
}

/* Confirmação antes de excluir + estado de carregamento nos formulários */
const dialogo = document.getElementById("confirmar");
let pendente = null;
document.addEventListener("submit", (e) => {
  const form = e.target;
  if (form.dataset.confirmar && dialogo) {
    e.preventDefault();
    pendente = form;
    document.getElementById("confirmar-msg").textContent = form.dataset.confirmar;
    document.getElementById("confirmar-ok").textContent = form.dataset.confirmarLabel || "Confirmar";
    dialogo.returnValue = "";
    dialogo.showModal();
  } else if (form.dataset.carregando) {
    const b = form.querySelector('button[type="submit"]');
    if (b) { b.textContent = form.dataset.carregando; setTimeout(() => { b.disabled = true; }, 0); }
  }
});
if (dialogo) {
  dialogo.addEventListener("close", () => {
    if (dialogo.returnValue === "ok" && pendente) pendente.submit();
    pendente = null;
  });
}

/* Bloqueio de login: contagem regressiva */
document.querySelectorAll("form[data-bloqueio]").forEach((form) => {
  let falta = Number(form.dataset.bloqueio);
  const b = form.querySelector('button[type="submit"]');
  const original = b.textContent;
  b.disabled = true;
  const tick = () => {
    if (falta <= 0) { b.disabled = false; b.textContent = original; return; }
    b.textContent = `Aguarde ${falta} s`;
    falta--;
    setTimeout(tick, 1000);
  };
  tick();
});
