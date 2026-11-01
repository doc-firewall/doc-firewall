document.addEventListener("DOMContentLoaded", function() {
    var titleElem = document.querySelector(".md-header__title .md-header__topic");
    var logoLink = document.querySelector(".md-header__button.md-logo");
    var homeUrl = logoLink ? logoLink.getAttribute("href") : ".";

    if (titleElem && titleElem.textContent.trim().includes("DocFirewall")) {
        titleElem.innerHTML = '<a href="' + homeUrl + '" style="color: inherit; text-decoration: none;"><span class="brand-doc">Doc</span><span class="brand-firewall">Firewall</span></a>';
    }
});
