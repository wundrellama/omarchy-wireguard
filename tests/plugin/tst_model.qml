import QtQuick
import QtTest
import "../../plugin/Model.js" as Model
TestCase {
  name: "WireGuardModel"
  function test_named() {
    var c = Model.parseCatalog('{"profiles":[{"id":"p","label":"Home","role":"internet-exit","source_name":"home.conf"}]}')
    compare(c.locations[0].label, "Home")
    compare(Model.connectArgs(c.locations[0]).join("|"), "connect|--profile|p")
    compare(Model.filterLocations(c.locations,"home.conf").length, 1)
    compare(Model.importReviewArgs(["/tmp/a.zip"],{"a.conf":"Home"}).join("|"), "import|--labels|{\"a.conf\":\"Home\"}|--|/tmp/a.zip")
  }
  function test_unknown() {
    compare(Model.parseStatus('{}').state,"unknown")
    compare(Model.parseStatus('{"mode":"disabled","enabled":true}').state,"unknown")
    compare(Model.parseStatus('{"mode":"disabled","enabled":true,"verified":false}').state,"unknown")
    compare(Model.parseStatus('{"mode":"connected","enabled":true,"verified":false}').state,"enabled-unverified")
    compare(Model.parseStatus('{"mode":"connected","enabled":"false"}').state,"unknown")
  }
  function test_pauseDoesNotPromiseProtection() {
    verify(Model.tooltip({state:"paused",countdown:60}).indexOf("Resumes in:") < 0)
  }
}
