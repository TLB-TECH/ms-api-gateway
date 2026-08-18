package br.com.controlefinanceiro.api.gateway.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtGatewayFilter implements GlobalFilter, Ordered {

    private final JwtService jwtService;

    // Rotas liberadas por caminho exato (não usar startsWith aqui: prefixos como
    // "/usuarios" vazariam "/usuarios/me" e outras rotas autenticadas do mesmo serviço).
    private static final List<String> ROTAS_PUBLICAS = List.of(
            "/auth/login",
            "/auth/recuperar-senha",
            "/auth/redefinir-senha"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        HttpMethod method = exchange.getRequest().getMethod();

        if (isRotaPublica(path, method)) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        if (!jwtService.isTokenValido(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }

    private boolean isRotaPublica(String path, HttpMethod method) {
        if (HttpMethod.POST.equals(method) && "/usuarios".equals(path)) {
            return true; // cadastro de novo usuário
        }
        if (HttpMethod.POST.equals(method) && "/webhooks/mercadopago".equals(path)) {
            return true; // notificação do Mercado Pago - autenticada por assinatura HMAC, não JWT
        }
        return ROTAS_PUBLICAS.stream().anyMatch(path::equals);
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
