'use strict';
// Minimal CModule+Stalker probe: count store instructions executed on a thread for ~1s.
const cm = new CModule(`
#include <gum/gumstalker.h>
#include <string.h>
extern volatile unsigned long long store_count;
volatile unsigned long long store_count = 0;
static void on_store (GumCpuContext * c, gpointer u) { store_count++; }
void transform (GumStalkerIterator * it, GumStalkerOutput * out, gpointer u) {
  const cs_insn * insn;
  while (gum_stalker_iterator_next (it, &insn)) {
    if (insn->mnemonic[0]=='s' && insn->mnemonic[1]=='t')
      gum_stalker_iterator_put_callout (it, on_store, 0, 0);
    gum_stalker_iterator_keep (it);
  }
}
`, { });
rpc.exports = {
  go: function(tid){
    try { Stalker.follow(tid, { transform: cm.transform }); return 'followed '+tid; }
    catch(e){ return 'follow-err '+e; }
  },
  read: function(){ return cm.store_count.readU64().toString(); },
  stop: function(tid){ try{Stalker.unfollow(tid); Stalker.flush();}catch(e){} return 'stopped'; }
};
send({t:'ready'});
