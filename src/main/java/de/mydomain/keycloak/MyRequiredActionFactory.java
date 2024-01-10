package de.mydomain.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class MyRequiredActionFactory implements RequiredActionFactory {

    @Override
    public String getId() {
        return MyRequiredAction.PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "My Update E-Mail";
    }

    @Override
    public RequiredActionProvider create(KeycloakSession keycloakSession) {
        return new MyRequiredAction();
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }
}
