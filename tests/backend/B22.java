// Test B22: Statement email templates

public String render(String template, Customer customer) {
    ExpressionParser parser = new SpelExpressionParser();
    Expression exp = parser.parseExpression(template,
        new TemplateParserContext());
    StandardEvaluationContext ctx = new StandardEvaluationContext(customer);
    return exp.getValue(ctx, String.class);
}
