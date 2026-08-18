package br.com.controlefinanceiro.api.gateway.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Roda depois do JwtGatewayFilter (order -1): quando o token ja e valido, confere se o
 * usuario tem acesso liberado (trial em andamento ou assinatura ativa) consultando ms-usuarios,
 * com um cache local de 60s pra nao bater no banco a cada request. Fail-open em caso de erro
 * na consulta - uma instabilidade interna nao pode bloquear todo mundo, inclusive quem pagou.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AssinaturaGatewayFilter implements GlobalFilter, Ordered {

    private final JwtService jwtService;
    private final WebClient webClient;

    @Value("${ms-usuarios.url}")
    private String msUsuariosUrl;

    @Value("${internal.secret}")
    private String internalSecret;

    private static final long CACHE_TTL_MS = 60_000;

    private static final List<String> ROTAS_LIBERADAS = List.of(
            "/auth/login",
            "/auth/recuperar-senha",
            "/auth/redefinir-senha"
    );

    private final ConcurrentMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        HttpMethod method = exchange.getRequest().getMethod();

        if (isRotaLiberada(path, method)) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange); // sem token: o JwtGatewayFilter ja bloqueou antes de chegar aqui
        }

        String email = jwtService.getEmailDoToken(authHeader.substring(7));
        if (email == null) {
            return chain.filter(exchange);
        }

        CacheEntry cacheado = cache.get(email);
        if (cacheado != null && cacheado.expiraEm() > System.currentTimeMillis()) {
            return cacheado.temAcesso() ? chain.filter(exchange) : bloquear(exchange, cacheado.status());
        }

        return consultarAcesso(email)
                .flatMap(entry -> {
                    cache.put(email, entry);
                    return entry.temAcesso() ? chain.filter(exchange) : bloquear(exchange, entry.status());
                })
                .onErrorResume(e -> {
                    log.warn("Falha ao consultar acesso do usuario {} em ms-usuarios, liberando por fail-open: {}",
                            email, e.getMessage());
                    return chain.filter(exchange);
                });
    }

    private Mono<CacheEntry> consultarAcesso(String email) {
        return webClient.get()
                .uri(msUsuariosUrl + "/interno/usuarios/{email}/acesso", email)
                .header("X-Internal-Secret", internalSecret)
                .retrieve()
                .bodyToMono(AcessoResponse.class)
                .map(resp -> new CacheEntry(resp.temAcesso(), resp.status(), System.currentTimeMillis() + CACHE_TTL_MS));
    }

    private Mono<Void> bloquear(ServerWebExchange exchange, String status) {
        exchange.getResponse().setStatusCode(HttpStatus.PAYMENT_REQUIRED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String corpo = "{\"erro\":\"Assinatura necessaria\",\"status\":\"" + status + "\"}";
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(corpo.getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    private boolean isRotaLiberada(String path, HttpMethod method) {
        if (HttpMethod.POST.equals(method) && "/usuarios".equals(path)) {
            return true;
        }
        if (path.startsWith("/usuarios/me/assinatura")) {
            return true;
        }
        if (path.startsWith("/webhooks/")) {
            return true;
        }
        return ROTAS_LIBERADAS.stream().anyMatch(path::equals);
    }

    @Override
    public int getOrder() {
        return 0;
    }

    private record CacheEntry(boolean temAcesso, String status, long expiraEm) {}

    private record AcessoResponse(boolean temAcesso, String status, Long diasRestantesTrial) {}
}
