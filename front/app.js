// Front del servicio de comentarios. Consume la API /secure a través del gateway.
const API = "/secure";

const list = document.getElementById("comments");
const form = document.getElementById("comment-form");
const statusLine = document.getElementById("status");
const filterInfo = document.getElementById("filter-info");

// Allowlist para el HTML de los comentarios: el mismo criterio que sanitize.py
// en el backend (formato básico y links https/mailto, nada más).
const PURIFY_CONFIG = {
  ALLOWED_TAGS: ["b", "i", "em", "strong", "p", "br", "ul", "ol", "li", "a", "code"],
  ALLOWED_ATTR: ["href", "title"],
  ALLOWED_URI_REGEXP: /^(?:https:|mailto:)/i,
};

if (window.DOMPurify) {
  // Los links de terceros no reciben window.opener ni Referer.
  DOMPurify.addHook("afterSanitizeAttributes", node => {
    if (node.tagName === "A") {
      node.setAttribute("rel", "noopener noreferrer nofollow");
      node.setAttribute("target", "_blank");
    }
  });
}

function renderRichText(container, html) {
  if (!window.DOMPurify) {
    // Falla cerrado: sin sanitizer, el comentario se muestra como texto plano.
    container.textContent = html;
    return;
  }
  container.replaceChildren(DOMPurify.sanitize(html, { ...PURIFY_CONFIG, RETURN_DOM_FRAGMENT: true }));
}

function renderFilterInfo(filter) {
  // El filtro sale de location.hash: lo controla quien arma el link. Solo texto.
  filterInfo.replaceChildren();
  if (!filter) return;
  const value = document.createElement("b");
  value.textContent = filter;
  const all = document.createElement("a");
  all.href = "#";
  all.textContent = "ver todos";
  filterInfo.append("Filtrando por: ", value, " · ", all);
}

function currentFilter() {
  // El filtro por autor viaja en el hash: /app/#alice
  try {
    return decodeURIComponent(location.hash.slice(1));
  } catch {
    return ""; // hash mal codificado (%E0%A4%A): se ignora
  }
}

async function loadComments() {
  const response = await fetch(`${API}/comments.json`);
  if (!response.ok) {
    statusLine.textContent = "No se pudieron cargar los comentarios.";
    return;
  }
  const comments = await response.json();
  const filter = currentFilter();

  renderFilterInfo(filter);

  list.replaceChildren();
  comments
    .filter(c => !filter || c.author === filter)
    .forEach(c => {
      const item = document.createElement("li");

      const author = document.createElement("a");
      author.className = "author";
      author.href = `#${encodeURIComponent(c.author)}`;
      author.textContent = c.author;

      const body = document.createElement("div");
      body.className = "body";
      // El comentario admite formato (negritas, links): se sanea con allowlist antes de insertarlo.
      renderRichText(body, c.body);

      item.append(author, body);
      list.append(item);
    });
}

form.addEventListener("submit", async event => {
  event.preventDefault();
  if (!form.checkValidity()) {
    statusLine.textContent = "Revisá los campos marcados.";
    form.classList.add("touched");
    return;
  }

  const response = await fetch(`${API}/comments`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ author: form.author.value, body: form.body.value }),
  });

  if (response.ok) {
    statusLine.textContent = "Comentario publicado.";
    form.reset();
    form.classList.remove("touched");
    loadComments();
  } else if (response.status === 422) {
    statusLine.textContent = "El servidor rechazó los datos. Revisá el usuario y el comentario.";
  } else if (response.status === 429) {
    statusLine.textContent = "Demasiados intentos. Esperá unos segundos.";
  } else {
    statusLine.textContent = "No se pudo publicar el comentario.";
  }
});

window.addEventListener("hashchange", loadComments);
loadComments();
