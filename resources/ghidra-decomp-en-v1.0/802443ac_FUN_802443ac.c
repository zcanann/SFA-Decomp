// Function: FUN_802443ac
// Entry: 802443ac
// Size: 24 bytes

uint FUN_802443ac(void)

{
  uint in_MSR;
  
  returnFromInterrupt(in_MSR,in_MSR & 0xffffffcf);
  return in_MSR & 0xffffffcf;
}

