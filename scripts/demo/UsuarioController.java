import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/usuarios")
public class UsuarioController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/buscar")
    public List<Map<String, Object>> buscarUsuario(@RequestParam String nome) {
        String sql = "SELECT id, nome, email, senha FROM usuarios WHERE nome = '" + nome + "'";
        return jdbcTemplate.queryForList(sql);
    }

    @PostMapping("/cadastrar")
    public String cadastrarUsuario(@RequestBody Usuario usuario) {
        String sql = "INSERT INTO usuarios (nome, email, senha) VALUES ('"
                   + usuario.getNome() + "', '"
                   + usuario.getEmail() + "', '"
                   + usuario.getSenha() + "')";
        jdbcTemplate.execute(sql);
        return "Usuário cadastrado com sucesso!";
    }

    @GetMapping("/dividir/{a}/{b}")
    public int dividir(@PathVariable int a, @PathVariable int b) {
        return a / b;
    }
}
