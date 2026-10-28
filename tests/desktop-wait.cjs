// Evaluate asynchronous IPC predicates in Node's awaited loop. A browser-side
// polling callback can otherwise treat a returned Promise as a truthy result.
async function waitForState(page,predicate,arg){
 const deadline=Date.now()+30000;
 while(Date.now()<deadline){if(await page.evaluate(predicate,arg))return;await page.waitForTimeout(50);}
 throw new Error('Desktop state condition timed out');
}
module.exports={waitForState};
