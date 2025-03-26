"use strict";

let blindSignatures = require("blind-signatures");
let SpyAgency = require("./spyAgency.js").SpyAgency;

function makeDocument(coverName) {
  return `The bearer of this signed document, ${coverName}, has full diplomatic immunity.`;
}

function blind(msg, n, e) {
  return blindSignatures.blind({
    message: msg,
    N: n,
    E: e,
  });
}

function unblind(blindingFactor, sig, n) {
  return blindSignatures.unblind({
    signed: sig,
    N: n,
    r: blindingFactor,
  });
}

let agency = new SpyAgency();

let documents = [];
let blindDocs = [];
let blindingFactors = [];

for (let i = 0; i < 10; i++) {
  let coverName = `Agent ${i + 1}`;
  let doc = makeDocument(coverName);
  documents.push(doc);

  let { blinded, r } = blind(doc, agency.n, agency.e);
  blindDocs.push(blinded);
  blindingFactors.push(r);
}

agency.signDocument(blindDocs, (selected, verifyAndSign) => {
  console.log(`Selected document index: ${selected}`);

  let verifiedDocs = documents.map((doc, index) =>
    index === selected ? undefined : doc
  );
  let verifiedFactors = blindingFactors.map((factor, index) =>
    index === selected ? undefined : factor
  );


  let blindedSignature = verifyAndSign(verifiedFactors, verifiedDocs);

  
  let signature = unblind(
    blindingFactors[selected],
    blindedSignature,
    agency.n
  );

  console.log(`Signed document: ${documents[selected]}`);
  console.log(`Signature: ${signature}`);
});
