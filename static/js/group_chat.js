const socket = io({ transports: ['websocket'], upgrade: false });

const chatBox = document.getElementById("chat-box");
const form = document.getElementById("chat-form");
const input = document.getElementById("message");

form.addEventListener("submit", function (e) {
  e.preventDefault();
  const msg = input.value.trim();
  if (msg) {
    socket.emit("send_message", msg);
    input.value = "";
  }
});

socket.on("receive_message", function (data) {
  const div = document.createElement("div");
  div.innerHTML = `<strong>${data.username}</strong>: ${data.message}`;
  chatBox.appendChild(div);
  chatBox.scrollTop = chatBox.scrollHeight;
});
