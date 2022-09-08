rule rule_name
{
    meta:
        description = "description"
        author = "author"
        date = "2022-09-08"
        reference = "reference"
        hash = "hash"
    strings:
        $name = "string"
    condition:
        all of them
}