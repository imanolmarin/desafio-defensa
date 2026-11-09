// Front del servicio de comentarios. Consume la API /secure a través del gateway.
const API = "/secure";

const list = document.getElementById("comments");
const form = document.getElementById("comment-form");
const statusLine = document.getElementById("status");
const filterInfo = document.getElementById("filter-info");

function currentFilter() {
  // El filtro por autor viaja en el hash: /app/#alice
  return decodeURIComponent(location.hash.slice(1));
}

async function loadComments() {
  const response = await fetch(`${API}/comments.json`);
  if (!response.ok) {
    statusLine.textContent = "No se pudieron cargar los comentarios.";
    return;
  }
  const comments = await response.json();
  const filter = currentFilter();

  // Muestra el filtro activo resaltado en negrita.
  filterInfo.innerHTML = filter ? `Filtrando por: <b>${filter}</b> · <a href="#">ver todos</a>` : "";

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
      // El comentario admite formato (negritas, links), por eso se inserta como HTML.
      body.innerHTML = c.body;

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
