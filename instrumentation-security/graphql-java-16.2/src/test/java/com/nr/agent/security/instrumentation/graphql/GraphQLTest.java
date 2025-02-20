package com.nr.agent.security.instrumentation.graphql;

import com.newrelic.agent.security.introspec.InstrumentationTestConfig;
import com.newrelic.agent.security.introspec.SecurityInstrumentationTestRunner;
import com.newrelic.agent.security.introspec.SecurityIntrospector;
import com.newrelic.api.agent.Trace;
import com.newrelic.api.agent.security.schema.HttpRequest;
import com.newrelic.api.agent.security.schema.HttpRequestCustomDataTypeEnum;
import com.newrelic.security.test.marker.Java8IncompatibleTest;
import graphql.ExecutionInput;
import graphql.ExecutionResult;
import graphql.GraphQL;
import graphql.execution.AsyncExecutionStrategy;
import graphql.execution.DefaultValueUnboxer;
import graphql.execution.Execution;
import graphql.execution.ExecutionContextBuilder;
import graphql.execution.ExecutionId;
import graphql.execution.ExecutionStepInfo;
import graphql.execution.ExecutionStrategy;
import graphql.execution.ExecutionStrategyParameters;
import graphql.execution.MergedField;
import graphql.execution.SubscriptionExecutionStrategy;
import graphql.execution.ValueUnboxer;
import graphql.execution.instrumentation.Instrumentation;
import graphql.execution.instrumentation.InstrumentationState;
import graphql.execution.instrumentation.SimpleInstrumentation;
import graphql.execution.instrumentation.parameters.InstrumentationCreateStateParameters;
import graphql.language.Document;
import graphql.language.Field;
import graphql.language.OperationDefinition;
import graphql.language.SelectionSet;
import graphql.schema.GraphQLEnumType;
import graphql.schema.GraphQLList;
import graphql.schema.GraphQLOutputType;
import graphql.schema.GraphQLSchema;
import graphql.schema.GraphQLSchemaElement;
import graphql.schema.GraphQLTypeVisitor;
import graphql.schema.StaticDataFetcher;
import graphql.schema.idl.RuntimeWiring;
import graphql.schema.idl.SchemaGenerator;
import graphql.schema.idl.SchemaParser;
import graphql.schema.idl.TypeDefinitionRegistry;
import graphql.schema.idl.TypeRuntimeWiring;
import graphql.util.TraversalControl;
import graphql.util.TraverserContext;
import org.dataloader.DataLoaderRegistry;
import org.junit.After;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

@RunWith(SecurityInstrumentationTestRunner.class)
@InstrumentationTestConfig(includePrefixes = { "graphql" })
@Category({ Java8IncompatibleTest.class })
public class GraphQLTest {

    private static final String TEST_ARG = "testArg";

    private static GraphQL graphQL;
    private static GraphQLSchema graphQLSchema;

    @BeforeClass
    public static void initialize() {
        String schema = "type Query{hello(" + TEST_ARG + ": String): String}";

        SchemaParser schemaParser = new SchemaParser();
        TypeDefinitionRegistry typeDefinitionRegistry = schemaParser.parse(schema);

        RuntimeWiring runtimeWiring = RuntimeWiring.newRuntimeWiring()
                .type("Query", builder -> builder.dataFetcher("hello",
                        new StaticDataFetcher("world")))
                .build();

        SchemaGenerator schemaGenerator = new SchemaGenerator();
        graphQLSchema = schemaGenerator.makeExecutableSchema(typeDefinitionRegistry, runtimeWiring);

        graphQL = GraphQL.newGraphQL(graphQLSchema).build();
    }

    @After
    public void cleanUp() {
        SecurityInstrumentationTestRunner.getIntrospector().clear();
    }

    @Test
    public void testQueryWithNoArg() {
        trace(createRunnable("{hello}"));
        assertCustomDataType();
    }

    @Test
    public void testQueryWithArg() {
        trace(createRunnable("{hello (" + TEST_ARG + ": \"fo)o\")}"));
        assertCustomDataType();
    }

    @Test
    public void testQueryWithVariables() throws ExecutionException, InterruptedException {
        // Graphql query with variables
        ExecutionInput executionInput = ExecutionInput.newExecutionInput().executionId(ExecutionId.generate()).query("{hello($arg: String!)}").variables(Collections.singletonMap("arg", "world")).build();
        Instrumentation instrumentation = new SimpleInstrumentation();
        InstrumentationState instrumentationState = instrumentation.createState(new InstrumentationCreateStateParameters(graphQLSchema, executionInput));

        Execution execution = new Execution(new AsyncExecutionStrategy(), new AsyncExecutionStrategy(), new SubscriptionExecutionStrategy(), instrumentation, new DefaultValueUnboxer());
        ExecutionId executionId = executionInput.getExecutionId();
        CompletableFuture<ExecutionResult> ans = execution.execute(Document.newDocument()
                        .definition(OperationDefinition.newOperationDefinition()
                                .selectionSet(SelectionSet.newSelectionSet().build())
                                .operation(OperationDefinition.Operation.QUERY).build())
                        .build(),
                graphQLSchema,
                executionId,
                executionInput,
                instrumentationState
                );
        ans.get();
        assertCustomDataTypes();
    }

    @Test
    public void testQueryWithoutVariables() throws ExecutionException, InterruptedException {
        // Graphql query without variables
        ExecutionInput executionInput = ExecutionInput.newExecutionInput().executionId(ExecutionId.generate()).query("{hello}").build();
        Instrumentation instrumentation = new SimpleInstrumentation();
        InstrumentationState instrumentationState = instrumentation.createState(new InstrumentationCreateStateParameters(graphQLSchema, executionInput));

        Execution execution = new Execution(new AsyncExecutionStrategy(), new AsyncExecutionStrategy(), new SubscriptionExecutionStrategy(), instrumentation, new DefaultValueUnboxer());
        ExecutionId executionId = executionInput.getExecutionId();
        CompletableFuture<ExecutionResult> ans = execution.execute(Document.newDocument()
                        .definition(OperationDefinition.newOperationDefinition()
                                .selectionSet(SelectionSet.newSelectionSet().build())
                                .operation(OperationDefinition.Operation.QUERY).build())
                        .build(),
                graphQLSchema,
                executionId,
                executionInput,
                instrumentationState
                );
        ans.get();
        assertCustomDataType();
    }

    @Test
    public void testParsingException() {
        //when
        trace(createRunnable("cause a parse error"));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        HttpRequest request = introspector.getSecurityMetaData().getRequest();
        Assert.assertTrue(request.getCustomDataType().isEmpty());
    }

    @Test
    public void validationException() {
        trace(createRunnable("{noSuchField}"));

        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        HttpRequest request = introspector.getSecurityMetaData().getRequest();
        Assert.assertTrue(request.getCustomDataType().isEmpty());
    }

    @Test
    public void testResolverException() {
        //given
        String query = "{hello " +
                "\n" +
                "bye}";

        //when
        trace(createRunnable(query, graphWithResolverException()));
        assertCustomDataType();
    }

    @Trace(dispatcher = true)
    private void trace(Runnable runnable) {
        runnable.run();
    }

    private Runnable createRunnable(final String query) {
        return () -> graphQL.execute(query);
    }

    private Runnable createRunnable(final String query, GraphQL graphql) {
        return () -> graphql.execute(query);
    }

    private GraphQL graphWithResolverException() {
        String schema = "type Query{hello(" + TEST_ARG + ": String): String" +
                "\n" +
                "bye: String!}";

        SchemaParser schemaParser = new SchemaParser();
        TypeDefinitionRegistry typeDefinitionRegistry = schemaParser.parse(schema);

        RuntimeWiring runtimeWiring = RuntimeWiring.newRuntimeWiring()
                .type(TypeRuntimeWiring.newTypeWiring("Query")
                        .dataFetcher("hello", environment -> {
                            throw new RuntimeException("waggle");
                        })
                        .dataFetcher("bye", environment -> null)
                )
                .build();

        SchemaGenerator schemaGenerator = new SchemaGenerator();
        GraphQLSchema graphQLSchema = schemaGenerator.makeExecutableSchema(typeDefinitionRegistry, runtimeWiring);

        return GraphQL.newGraphQL(graphQLSchema).build();
    }


    private void assertCustomDataType() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        HttpRequest request = introspector.getSecurityMetaData().getRequest();
        Assert.assertFalse(request.getCustomDataType().isEmpty());
        Assert.assertEquals(Collections.singletonMap("*.query", HttpRequestCustomDataTypeEnum.GRAPHQL_QUERY.name()), request.getCustomDataType());
    }

    private void assertCustomDataTypes() {
        SecurityIntrospector introspector = SecurityInstrumentationTestRunner.getIntrospector();
        HttpRequest request = introspector.getSecurityMetaData().getRequest();
        Assert.assertFalse(request.getCustomDataType().isEmpty());
        Map<String, String> expectedCustomDataType = new HashMap<>();
        expectedCustomDataType.put("*.query", HttpRequestCustomDataTypeEnum.GRAPHQL_QUERY.name());
        expectedCustomDataType.put("*.variables", HttpRequestCustomDataTypeEnum.GRAPHQL_VARIABLE.name());

        Assert.assertEquals(expectedCustomDataType, request.getCustomDataType());
    }
}
