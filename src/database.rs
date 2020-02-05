use lazy_static::lazy_static;
use rocksdb::DB;
use crate::utils::*;
lazy_static!{
    static ref DATABASE : DB = {
        let data_path = get_var("PASSKEEPER_DATA_PATH");
        DB::open_default(data_path).unwrap_or_else(failed_with("unable to open data base"))
    };
}

#[inline(always)]
pub fn get_database() -> &'static DB {
    &* DATABASE
}