# Reverse Me 2
**Category: Android Reverse Engineering**

The application just shows a logo and a button to "UPDATE FLAGS". After clicking the button, some passwords pop up.

<img width=30% src=images/app.png></img>

The first thing to do is to decompile the APK and look at the source code. 

Clicking the button runs this logic:
```java
protected DatabaseReference ref = this.db.getReference("flags");
...
public void onClick(View v) {
    MainActivity.this.ref.addValueEventListener(new ValueEventListener() {
        public void onDataChange(DataSnapshot dataSnapshot) {
            String data = ((Map) dataSnapshot.getValue()).toString();
            MainActivity.this.flags.setText(data.substring(1, data.length() - 1).replace(", ", "\n").replace("=", " : "));
        }

        public void onCancelled(DatabaseError databaseError) {
            Log.w("CTF", "Failed to read DB", databaseError.toException());
        }
    });
    Toast.makeText(MainActivity.this, "Updating Firebase database...", 0).show();
}
```

The data is being loaded from the `flags` endpoint of an external Firebase source. I took a look at `strings.xml` to see the connection information.

```xml
<string name="firebase_database_url">https://reverse-me-2.firebaseio.com</string>
```

I thought I'd check if the database was secured properly. I queried the rest endpoint at `https://reverse-me-2.firebaseio.com/.json` to see if I could access all the records unauthenticated.

It worked! We see the `flags` data that appear in the app, and another property, `secret`, which has our flag:
```json
{
    "flags": {
        "HackTheBox-OpenAdmin-root": "06afcd5d4e323ab09f",
        "HackTheBox-OpenAdmin-user": "badc67e540ceb82ead264",
        "Root-Me-App-Script": "iuezçz_rhqçHD_oqhE_2Gr",
        "Root-Me-App-Systeme": "sjefh_z87Y2Q87E287Oerg",
        "Root-Me-Cracking": "uqb_QZ dg_GQ2_e gQ28e",
        "Root-Me-Prog": "qjzg-èqTDQ87D_729E8H298E",
        "Root-Me-Web": "iusebf_zujfz"
    },
    "secret": {
        "InterIUT-Reverse": "H2G2{f1r3basE_iS_v3ry_s3cure}"
    }
}
```