path "+/data/*" { capabilities = ["read","create","sudo","delete", "update", "list"]}

path "+/metadata/*" { capabilities = ["read","create","sudo","delete", "update", "list"]}

path "idl-vault/+/metadata/*" { capabilities = ["read","create","sudo","delete", "update", "list"]}

path "idl-vault/+/data/*" { capabilities = ["read","create","sudo","delete", "update", "list"]}

path "+/delete/*" { capabilities = ["read","create","sudo","delete", "update", "list"]}

path "idl-vault/+/delete/*" { capabilities = ["read","create","sudo","delete", "update", "list"]}