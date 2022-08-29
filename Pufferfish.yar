rule Test_Rule
{
    meta:
        description = "some fancy test rule"
        author = "david"
        date = "2022-08-29"
        reference = "Testinggg"
        hash = "some dummy hash lol"
    strings:
        $name = "Niklaus"
    condition:
        all of them
}