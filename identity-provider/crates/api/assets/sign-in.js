// The pages' only script, served from here so the CSP allows no other: a form on its way shows
// it, and can't be sent twice. Disabled after the submit event, the button doesn't stop the send.
for (const form of document.querySelectorAll("form")) {
    form.addEventListener("submit", (event) => {
        const button = event.submitter ?? form.querySelector("button[type=submit]")
        if (!button) return
        if (button.classList.contains("is-busy")) {
            event.preventDefault()
            return
        }
        button.classList.add("is-busy")
        button.setAttribute("aria-busy", "true")
        setTimeout(() => {
            button.disabled = true
        })
    })
}

// A page brought back from the back-forward cache is ready to send again.
window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return
    for (const button of document.querySelectorAll("button.is-busy")) {
        button.classList.remove("is-busy")
        button.removeAttribute("aria-busy")
        button.disabled = false
    }
})
