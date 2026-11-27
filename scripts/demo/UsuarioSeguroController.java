import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/usuarios")
public class UsuarioSeguroController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/buscar")
    public ResponseEntity<List<UsuarioDTO>> buscarUsuario(@RequestParam String nome) {
        String sql = "SELECT id, nome, email FROM usuarios WHERE nome = ?";
        List<UsuarioDTO> usuarios = jdbcTemplate.query(sql, new Object[]{nome}, (rs, rowNum) ->
            new UsuarioDTO(rs.getLong("id"), rs.getString("nome"), rs.getString("email"))
        );
        return ResponseEntity.ok(usuarios);
    }

    @PostMapping("/cadastrar")
    public ResponseEntity<String> cadastrarUsuario(@RequestBody UsuarioRequest request) {
        String senhaCriptografada = passwordEncoder.encode(request.getSenha());
        String sql = "INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)";
        jdbcTemplate.update(sql, request.getNome(), request.getEmail(), senhaCriptografada);
        return ResponseEntity.ok("Usuário cadastrado com segurança!");
    }
}
