
create table if not exists brc20_accounts (
    address varchar(64) not null,
    ty integer not null,
    primary key(address)
);

