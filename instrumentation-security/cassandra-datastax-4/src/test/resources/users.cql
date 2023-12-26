CREATE TABLE users (email text, age int, PRIMARY KEY (email));
CREATE TABLE users2 (
    id uuid PRIMARY KEY,
    email text,
    age int,
    isMarried boolean,
    img blob,
    phone decimal,
    dob DATE,
    name varchar,
    events list<text>,
    address set<text>,
    marks map<text,int>
);
