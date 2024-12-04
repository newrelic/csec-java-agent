package com.nr.agent.instrumentation.solr4;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.operation.SolrDbOperation;
import org.apache.solr.client.solrj.SolrQuery;
import org.apache.solr.client.solrj.SolrServerException;
import org.apache.solr.client.solrj.impl.HttpSolrServer;
import org.apache.solr.client.solrj.request.UpdateRequest;
import org.apache.solr.common.SolrInputDocument;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = "org.apache.solr")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SolrTest {

    private static GenericContainer<?> solrServer;

    private static HttpSolrServer solr;

    private static final String CORE = "myCore";

    private static String url;

    private static final HashMap<String, String> params = new HashMap<>();

    @BeforeClass
    public static void setup() throws InterruptedException, IOException, SolrServerException {
        int PORT = SecurityInstrumentationTestRunner.getIntrospector().getRandomPort();
        url = String.format("http://localhost:%s/solr/%s", PORT, CORE);

        solrServer = new GenericContainer<>(DockerImageName.parse("solr:8"));
        solrServer.setPortBindings(Collections.singletonList(PORT + ":8983"));
        solrServer.start();
        solrServer.execInContainer("solr", "start");
        solrServer.execInContainer("solr", "create", "-c", CORE);

        solr = new HttpSolrServer(url);

        solr.add(getDocument("ish", 4, "abc"));
        solr.add(getDocument("ish", 5, "abc"));
        solr.add(getDocument("ish", 6, "abc"));
        params.put("waitSearcher", "true");
        params.put("commit", "true");
        params.put("softCommit", "false");
    }

    @AfterClass
    public static void tearDown() {
        if (solrServer != null){
            solrServer.stop();
            solrServer.close();
        }
    }

    private static SolrInputDocument getDocument(String name, int id, String city) {
        SolrInputDocument document = new SolrInputDocument();
        document.addField("id", id);
        document.addField("name", name);
        document.addField("Phone No", Collections.singletonList("9876543210"));
        document.addField("City", city);
        return document;
    }

    @Test
    public void addDocumentTest() throws SolrServerException, IOException {
        SolrInputDocument document = getDocument("Ishi", 1, "Pune");
        solr.add(document);
        solr.commit();
        assertSolrOperation("POST", "/update", document);
    }

    @Test
    public void addMultiDocumentsTest() throws SolrServerException, IOException {
        SolrInputDocument document1 = getDocument("Harry", 2, "Hogwarts");
        SolrInputDocument document2 = getDocument("Ron", 3, "Mumbai");
        solr.add(document1);
        solr.add(document2);
        solr.commit();
        assertSolrOperation("POST", "/update", document1, document2);
    }

    @Test
    public void updateDocument1Test() throws SolrServerException, IOException {
        SolrInputDocument document = getDocument("Ron", 3, "Hogwarts");
        UpdateRequest request = new UpdateRequest();
        request.setAction(UpdateRequest.ACTION.COMMIT, false, true);
        request.add(document);
        request.process(solr);
        assertSolrOperation("POST", "/update", document);
    }

    @Test
    public void updateDocument2Test() throws SolrServerException, IOException {
        SolrInputDocument document = getDocument("Ron", 3, "Hogwarts");
        UpdateRequest request = new UpdateRequest();
        request.setAction(UpdateRequest.ACTION.COMMIT, false, true, false);
        request.add(document);
        solr.request(request);
        assertSolrOperation("POST", "/update", document);
    }

    @Test
    public void deleteDocument1Test() throws SolrServerException, IOException {
        solr.deleteById("1");
        assertSolrOperation("POST", "/update");
    }

    @Test
    public void deleteDocument2Test() throws SolrServerException, IOException {
        UpdateRequest request = new UpdateRequest();
        request.deleteById("1");
        request.process(solr);
        assertSolrOperation("POST", "/update");
    }

    @Test
    public void deleteDocument3Test() throws SolrServerException, IOException {
        UpdateRequest request = new UpdateRequest();
        request.deleteByQuery("City:abc");
        request.process(solr);
        assertSolrOperation("POST", "/update");
    }

    @Test
    public void zQueryDataTest() throws SolrServerException, IOException {
        SolrQuery query = new SolrQuery();
        query.setQuery("*:*");
        query.addField("*");

        params.clear();
        params.put("q", "*:*");
        params.put("fl", "*");

        solr.query(query);
        assertSolrOperation("GET", "/select");
    }

    @Test
    public void zQueryData2Test() throws SolrServerException, IOException {
        SolrQuery query = new SolrQuery();
        query.set("q", "City:abc");
        query.addField("id");

        solr.query(query);
        params.clear();
        params.put("q", "City:abc");
        params.put("fl", "id");
        assertSolrOperation("GET", "/select");
    }

    @Test
    public void zQueryData3Test() throws SolrServerException, IOException {
        SolrQuery query = new SolrQuery();
        query.set("q", "id:1");
        query.addField("*");
        query.addFacetQuery("City");
        solr.query(query);

        params.clear();
        params.put("q", "id:1");
        params.put("fl", "*");
        params.put("facet", "true");
        params.put("facet.query", "City");
        assertSolrOperation("GET", "/select");
    }

    @Test
    public void pingTest() throws SolrServerException, IOException {
        solr.ping();
        assertSolrOperation("GET", "/admin/ping");
    }


    private void assertSolrOperation(String method, String path, SolrInputDocument... docs){
        List<AbstractOperation> operations = SecurityInstrumentationTestRunner.getIntrospector().getOperations();
        Assert.assertNotNull(operations);
        int i = 0;
        Assert.assertFalse(operations.isEmpty());
        for (AbstractOperation op : operations) {
            Assert.assertTrue(op instanceof SolrDbOperation);
            SolrDbOperation operation = (SolrDbOperation) op;

            // TODO: discuss collection definition in instrumentation
            Assert.assertEquals("solr/"+ CORE, operation.getCollection());

            Assert.assertEquals(method, operation.getMethod());
            Assert.assertEquals(path, operation.getPath());
            Assert.assertEquals(url, operation.getConnectionURL());
            if (operation.getDocuments() != null && !operation.getDocuments().isEmpty()) {
                Assert.assertEquals(docs[i].size(), ((SolrInputDocument)(operation.getDocuments().get(0))).size());
                Assert.assertEquals(docs[i], operation.getDocuments().get(0));
                ++i;
            }
            if (operation.getParams() != null && !operation.getParams().isEmpty()) {
                Assert.assertEquals(SolrTest.params.size(), operation.getParams().size());
                Assert.assertEquals(SolrTest.params, operation.getParams());
            }
        }
    }
}
