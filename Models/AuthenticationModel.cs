using FluentValidation;
using System;
using System.Linq;
using Trivial.Security;

namespace rde.edu.do_jericho_walls.Models
{
    public class AuthenticationModel
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class AuthenticationSecrets
    {
        public int Id { get; set; }
        public string Password { get; set; }
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public bool Active { get; set; }
    }

    public class AuthenticationJWT : JsonWebTokenPayload
    {
        public UserModel Payload { get; set; }
    }

    public class AuthorizationModel
    {
        public UserModel User { get; set; }
        public bool Forbiden { get; set; }
    }

    public class AuthenticationModelValidator : AbstractValidator<AuthenticationModel>
    {
        public AuthenticationModelValidator()
        {
            RuleFor(m => m.Email)
               .Cascade(CascadeMode.StopOnFirstFailure)
               .NotEmpty().WithMessage("El {PropertyName} es requerido.")
               .EmailAddress().WithMessage("El {PropertyName} es invalido.")
               .WithName("correo electrónico");

            RuleFor(m => m.Password)
               .Cascade(CascadeMode.StopOnFirstFailure)
               .NotEmpty().WithMessage("La {PropertyName} es requerida.")
               .Length(8, -1).WithMessage("La {PropertyName} debe tener mínimo {MinLength} caracteres. La {PropertyName} tiene una longitud de {TotalLength}")
               .Must(ValidPassword).WithMessage("La {PropertyName} debe tener mínimo un dígito, una letra mayúscula y otra minúscula.")
               .WithName("contraseña");
        }

        protected bool ValidName(string name)
        {
            name = name.Trim();
            name = name.Replace(" ", "");
            return name.All(Char.IsLetter);
        }

        static bool ValidPassword(string password)
        {
            bool hasUpperCaseLetter = false;
            bool hasLowerCaseLetter = false;
            bool hasDecimalDigit = false;

            foreach (char c in password)
            {
                if (char.IsUpper(c)) hasUpperCaseLetter = true;
                else if (char.IsLower(c)) hasLowerCaseLetter = true;
                else if (char.IsDigit(c)) hasDecimalDigit = true;
            }

            return hasUpperCaseLetter && hasLowerCaseLetter && hasDecimalDigit;
        }
    }
}
