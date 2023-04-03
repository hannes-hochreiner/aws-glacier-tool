export def start [] {
  watch . {|| cargo test}
}

export def test [] {
  cargo build
  cargo test
}

export def run [
  ...args: string
] {
  cargo build
  sudo systemd-creds decrypt env.json.enc | from json | load-env
  cargo run -- $args
}

export def create_env_file [] {
  let rec = {
    "AWS_REGION": (input "AWS region: "),
    "AWS_KEY_ID": (input "AWS key id: "),
    "AWS_SECRET_KEY": (input -s "AWS secret key: ")
  }
  $rec | to json | run-external --redirect-stdout "sudo" "systemd-creds" "encrypt" "--name=env.json.enc" "-" "-" | save -f env.json.enc
}