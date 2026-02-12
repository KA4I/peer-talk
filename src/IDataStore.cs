using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace PeerTalk
{
    /// <summary>
    ///   A data store for name value pairs.
    /// </summary>
    /// <typeparam name="TName">
    ///   The type used for a unique name.
    /// </typeparam>
    /// <typeparam name="TValue">
    ///   The type used for the value.
    /// </typeparam>
    public interface IDataStore<TName, TValue> where TValue : class
    {
        /// <summary>
        ///   Get the value with the specified name.
        /// </summary>
        /// <param name="name">
        ///   The unique name of the entity.
        /// </param>
        /// <param name="cancel">
        ///   Is used to stop the task.  When cancelled, the <see cref="TaskCanceledException"/> is raised.
        /// </param>
        /// <returns>
        ///   A task that represents the asynchronous operation. The task's result is
        ///   a <typeparamref name="TValue"/>
        /// </returns>
        /// <exception cref="KeyNotFoundException">
        ///   When the <paramref name="name"/> does not exist.
        /// </exception>
        Task<TValue> GetAsync(TName name, CancellationToken cancel = default(CancellationToken));

        /// <summary>
        ///   Put the value with the specified name.
        /// </summary>
        /// <param name="name">
        ///   The unique name of the entity.
        /// </param>
        /// <param name="value">
        ///   The entity.
        /// </param>
        /// <param name="cancel">
        ///   Is used to stop the task.  When cancelled, the <see cref="TaskCanceledException"/> is raised.
        /// </param>
        /// <returns>
        ///   A task that represents the asynchronous operation.
        /// </returns>
        /// <remarks>
        ///   If <paramref name="name"/> already exists, it's value is overwriten.
        ///   <para>
        ///   The file is deleted if an exception is encountered.
        ///   </para>
        /// </remarks>
        Task PutAsync(TName name, TValue value, CancellationToken cancel = default(CancellationToken));

        /// <summary>
        ///   Remove the value with the specified name.
        /// </summary>
        /// <param name="name">
        ///   The unique name of the entity.
        /// </param>
        /// <param name="cancel">
        ///   Is used to stop the task.  When cancelled, the <see cref="TaskCanceledException"/> is raised.
        /// </param>
        /// <returns>
        ///   A task that represents the asynchronous operation.
        /// </returns>
        /// <remarks>
        ///   A non-existent <paramref name="name"/> does nothing.
        /// </remarks>
        Task RemoveAsync(TName name, CancellationToken cancel = default(CancellationToken));

        /// <summary>
        ///   Determines if the name exists.
        /// </summary>
        /// <param name="name">
        ///   The unique name of the entity.
        /// </param>
        /// <param name="cancel">
        ///   Is used to stop the task.  When cancelled, the <see cref="TaskCanceledException"/> is raised.
        /// </param>
        /// <returns>
        ///   A task that represents the asynchronous operation. The task's result is
        ///   <b>true</b> if the <paramref name="name"/> exists.
        /// </returns>
        Task<bool> ExistsAsync(TName name, CancellationToken cancel = default(CancellationToken));
    }
}