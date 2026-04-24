// Function: FUN_8025d124
// Entry: 8025d124
// Size: 60 bytes

void FUN_8025d124(uint param_1)

{
  *(uint *)(DAT_803dc5a8 + 0x80) = *(uint *)(DAT_803dc5a8 + 0x80) & 0xffffffc0 | param_1;
  FUN_8025d490(0);
  return;
}

