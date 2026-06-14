## This folder is specifically here to store the TailwindCSS CLI

Decided against using NPM because of paranoia about possible supply chain attacks.
This folder is here to hold the TailwindCSS standalone CLI tool.
But can be used to hold other build tools for the project as well, as needed.

The version shipped with the project runs on glibc Linux but you can head to the tailwind project and download CLI
tools for other platforms like musl-Linux or MacOS or Windows as well at [the releases page](https://github.com/tailwindlabs/tailwindcss/releases)

The tailwindcss tool needs to read the templates in the `templates` folder in the project root and spit out a `app.css` file into the `static` folder. The project will NOT error if these files are not found, but your frontend will likely be borked.