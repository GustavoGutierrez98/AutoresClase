using System.ComponentModel.DataAnnotations;

namespace AutoresClase.DTOS
{
    public class AgregarRol
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
