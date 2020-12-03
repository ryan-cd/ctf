# MonSQL Injection 1
**Category: Web**

This challenge page shows a wall of text, and a text input box:

<img width=80% src=images/app.png></img>

This box allows us to enter "MonSQL" commands. There is a hint in the last sentence, "Contenant au moins la table utilisateurs", which means we have at the very least a users table named "utilisateurs".

The challenge included a cheat sheet explaining how to use MonSQL:

![cheatsheet](images/cheatsheet.svg)

Let's start by doing a simple select statement. In normal SQL we would write `SELECT * FROM utilisateurs;`. According to the cheat sheet:

|MySQL   |MonSQL   |
|---|---|
| SELECT  | SÉLECTIONNE  |
|  * | TOUT  |
|  FROM | ÀPARTIRDE  |

Putting it together, we get: `SÉLECTIONNE+TOUT+ÀPARTIRDE+utilisateurs;`

Sending this query to the API returns the users. Nothing too interesting here though. We should try and figure out what other tables are available. 

In MySQL, the command we'd want is `SHOW TABLES;`. Again, we consult the cheat sheet to put together a query _en français_.

|MySQL   |MonSQL   |
|---|---|
| SHOW  | MONTREMOI  |
|  TABLES | LESTABLES  |

Sending `MONTREMOI LESTABLES;` gives us the following:
```json
{"r\u00e9sultat":[["reponses"],["utilisateurs"]],"statut":"ok"}
```

Let's take a look at what `reponses` is all about. `SÉLECTIONNE+TOUT+ÀPARTIRDE+reponses;`:

```json
{"r\u00e9sultat":[[1,"H2G2{j_3sper3_qu3_v0us_4v3z_tr0uv3_ca_f4cil3_?}"]],"statut":"ok"}
```

Flag captured: `H2G2{j_3sper3_qu3_v0us_4v3z_tr0uv3_ca_f4cil3_?}`