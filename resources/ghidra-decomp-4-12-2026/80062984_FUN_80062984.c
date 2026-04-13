// Function: FUN_80062984
// Entry: 80062984
// Size: 140 bytes

void FUN_80062984(void)

{
  if (DAT_803dc2b8 == '\0') {
    return;
  }
  DAT_803ddb78 = 0;
  DAT_803ddb7c = 0;
  DAT_803ddb6c = '\x01' - DAT_803ddb6c;
  DAT_803ddb6d = '\x01' - DAT_803ddb6d;
  DAT_803ddb6e = '\x01' - DAT_803ddb6e;
  DAT_803ddb88 = *(undefined4 *)(&DAT_803ddba4 + DAT_803ddb6c * 4);
  DAT_803ddb74 = 0;
  DAT_803ddb90 = DAT_803ddba0;
  DAT_803ddb98 = DAT_803ddb9c;
  DAT_803ddb84 = *(undefined4 *)(&DAT_803ddba4 + DAT_803ddb6c * 4);
  DAT_803ddb94 = DAT_803ddb9c;
  DAT_803ddb8c = DAT_803ddba0;
  return;
}

