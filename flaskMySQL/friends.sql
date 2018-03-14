create table emails (
	id int primary key unique auto_increment not null,
    email varchar(64),
    date_created datetime
)