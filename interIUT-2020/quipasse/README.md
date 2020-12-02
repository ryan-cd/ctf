# Quipasse
**Category: Android Reverse Engineering**

Opening up the application, we are greeted by a password screen:

<img width=30% src=images/app.png></img>

Let's decompile, and look at the source for clues.

This is the code that runs on the button press:
```java
// MainActivity.java
public void onClick(View v) {
    Intent intent = new Intent(MainActivity.this, DbActivity.class);
    String password = ((EditText) MainActivity.this.findViewById(R.id.dbPassword)).getText().toString();
    if (password.isEmpty()) {
        Toast.makeText(MainActivity.this, "Il faudrait penser à choisir un mot de passe.", 0).show();
    } else if (password.matches("-?[0-9a-fA-F]+")) {
        intent.putExtra("password", password);
        MainActivity.this.startActivity(intent);
    } else {
        Toast.makeText(MainActivity.this, "Ça ne ressemble pas vraiment à une clé ça.", 0).show();
    }
}
```

We can see that there is a regex match to ensure the password conforms to an expected character set. If the characters are correct, we launch the DbActivity:

```java
// DbActivity.java
private String[] encryptedPasses = {"BS/MgnUEep/nCC1aAK/aB5mJAKfRGn3T03/sePM8nVv9nn36UZZvi+/bsqHnaKtc", "Rly34A8V98gY467cQy6JfLZa/PNjtEXyxdyGva6pScZmEtMKsaaHv88wxvKDB44OoSqO0HPcbUpvp8tD2rCSlw==", "U+HaCImq6DmIKc+9rzhf41tbcPuXg0UCrEGPdmzMBdFRMC/mbVg+ITC+zvkJZi4PO2dhIg0PcnSPIlSt1VJzWw==", "YIY1M4r5M9cy1EgmB9WGB6ULTopi+b7MuJKsl82JCLr+P6FAJhwr4XDxbTL6Qw2m", "1NJxkx1uM5X6feZaCWa0nluQwrc0NF4xo69I2Uw0aJ0au4o0KfrzUPpQynxQB+nU", "szQ1W/w93pvU4wk3WXMkLYG7tuUsP55f2r915PmOkHJI9LVuAXMEFKhS+7Vl/HllZx+Mb2ILzjDSW1xqvdPg/fwidsy+WWpHatPnDDEToy8="};
...
public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView((int) R.layout.flags_activity);
    byte[] password = EntryList.hexStringToByteArray(getIntent().getStringExtra("password"));
    ArrayList<Entry> decryptedPasses = new ArrayList<>();
    for (String bytes : this.encryptedPasses) {
        try {
            decryptedPasses.add(Entry.newEntrySerialized(new String(decrypt(password, Base64.getDecoder().decode(bytes.getBytes())), StandardCharsets.UTF_8)));
        } catch (Exception e) {
            Toast.makeText(this, "On dirait que ce n'est pas la bonne clé :'(", 0).show();
        }
    }
    EntryList entries = new EntryList(this, (Entry[]) decryptedPasses.toArray(new Entry[0]));
    ListView listView2 = (ListView) findViewById(R.id.flagList);
    this.listView = listView2;
    listView2.setAdapter(entries);
}
```

Looks like the entered password needs to be able to decrypt some data. I looked in `strings.xml` to see if there was anything there that could help. Something really interesting popped up:
```xml
<string name="secret_key">B224589A65B8E5BF5C36ABF3DC48CFA2607044BEA72C796104087AEF576503BC</string>
```

Entering this into the application did the trick, and we were sent to this screen:

<img width=30% src=images/app-solved.png></img>

H2G2{r0n4n_L4CH3_C3TT3_APK!}
